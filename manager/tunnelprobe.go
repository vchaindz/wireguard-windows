/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"log"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// A probe must be over before the next sample at one per second is taken, so that each sample reports the
// probe sent at the one before.
const probeTimeout = 900 * time.Millisecond

// probeTargetUsable reports whether an address can be sent a single echo request.
func probeTargetUsable(addr netip.Addr) bool {
	return addr.IsValid() && addr.Zone() == "" && !addr.IsUnspecified() && !addr.IsMulticast() &&
		!(addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}))
}

// probeTarget chooses the address to measure: the one set for the tunnel; failing that its first DNS server,
// which is normally reached through the tunnel and answers pings; failing that the first allowed IP of a peer
// that is a single host, which is usually the peer's own tunnel address. Networks are not guessed into hosts. An
// invalid address means there is nothing to measure.
func probeTarget(config *conf.Config, setting string) netip.Addr {
	if setting != "" {
		if addr, err := netip.ParseAddr(setting); err == nil && probeTargetUsable(addr) {
			return addr.Unmap()
		}
	}
	if config == nil {
		return netip.Addr{}
	}
	for _, addr := range config.Interface.DNS {
		if probeTargetUsable(addr) {
			return addr.Unmap()
		}
	}
	for i := range config.Peers {
		for _, prefix := range config.Peers[i].AllowedIPs {
			if prefix.IsSingleIP() && probeTargetUsable(prefix.Addr()) {
				return prefix.Addr().Unmap()
			}
		}
	}
	return netip.Addr{}
}

// probeTally is what the probes that finished since the last sample found.
type probeTally struct {
	sent, lost  uint16
	totalMicros uint64 // Sum of the round trips of the answered probes.
	maxMicros   uint32
}

func (t *probeTally) answered(rtt time.Duration) {
	// At least a microsecond, so that a latency of zero always means that nothing was answered.
	micros := uint32(min(max(rtt.Microseconds(), 1), 0xffffffff))
	t.sent = saturatingAdd16(t.sent, 1)
	t.totalMicros += uint64(micros)
	t.maxMicros = max(t.maxMicros, micros)
}

func (t *probeTally) unanswered() {
	t.sent = saturatingAdd16(t.sent, 1)
	t.lost = saturatingAdd16(t.lost, 1)
}

// fill records the tally in a sample. A sample with no finished probe stays unprobed, so that time without
// measurements is not shown as a latency of zero.
func (t probeTally) fill(sample *TunnelSample) {
	if t.sent == 0 {
		return
	}
	sample.Probed = true
	sample.ProbesSent, sample.ProbesLost = t.sent, t.lost
	if answered := uint64(t.sent - t.lost); answered > 0 {
		sample.LatencyMicros = uint32(t.totalMicros / answered)
	}
	sample.MaxLatencyMicros = t.maxMicros
}

type probeRequest struct {
	target netip.Addr
	luid   winipcfg.LUID
}

// A tunnelProber sends echo requests through one tunnel. The requests block for up to probeTimeout, so they run
// in a goroutine of their own and the health monitor only hands over requests and collects tallies.
type tunnelProber struct {
	requests chan probeRequest
	stop     chan struct{}
	done     chan struct{}

	lock  sync.Mutex
	tally probeTally
}

func startTunnelProber(tunnelName string) *tunnelProber {
	prober := &tunnelProber{
		requests: make(chan probeRequest, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go prober.run(tunnelName)
	return prober
}

// request asks for one probe. If the previous request has not been taken up yet, this one is dropped, so that
// a slow probe does not build up a queue.
func (prober *tunnelProber) request(target netip.Addr, luid winipcfg.LUID) {
	select {
	case prober.requests <- probeRequest{target, luid}:
	default:
	}
}

// take returns the tally of the probes that finished since the last call, and starts a new one.
func (prober *tunnelProber) take() probeTally {
	prober.lock.Lock()
	defer prober.lock.Unlock()
	tally := prober.tally
	prober.tally = probeTally{}
	return tally
}

// close tells the prober to finish. It does not wait: a probe in flight ends within probeTimeout, after which
// the prober closes its handles by itself, and nothing it does touches the tunnel's adapter.
func (prober *tunnelProber) close() {
	close(prober.stop)
}

func (prober *tunnelProber) run(tunnelName string) {
	defer close(prober.done)
	var handles [2]*icmpHandle
	defer func() {
		for _, h := range handles {
			h.close()
		}
	}()
	var lastProblem string
	for {
		var req probeRequest
		select {
		case <-prober.stop:
			return
		case req = <-prober.requests:
		}
		ipv6 := !req.target.Is4()
		family := 0
		if ipv6 {
			family = 1
		}
		var rtt time.Duration
		source, err := tunnelSourceAddress(req.luid, ipv6)
		if err == nil && handles[family] == nil {
			handles[family], err = openICMP(ipv6)
		}
		if err == nil {
			rtt, err = handles[family].echo(source, req.target, probeTimeout)
		}
		select {
		case <-prober.stop:
			return
		default:
		}
		prober.lock.Lock()
		switch err {
		case nil:
			prober.tally.answered(rtt)
		case errProbeLost:
			prober.tally.unanswered()
		}
		prober.lock.Unlock()

		// Not having an address is expected while the tunnel waits for its peer before configuring itself, so
		// only other problems are worth a line, and only when they change.
		problem := ""
		if err != nil && err != errProbeLost && err != errNoTunnelAddress {
			problem = err.Error()
		}
		if problem != lastProblem {
			if problem != "" {
				log.Printf("[%s] Warning: connection quality: unable to send a probe to %v: %s", tunnelName, req.target, problem)
			} else if lastProblem != "" {
				log.Printf("[%s] Connection quality: probes to %v are being sent again", tunnelName, req.target)
			}
			lastProblem = problem
		}
	}
}

var errNoTunnelAddress = errors.New("the tunnel has no address of this family")

// tunnelSourceAddress returns an address of the tunnel's own interface. Windows sends from an address only
// through the interface that has it, so using it as the source makes the probe go through the tunnel, and its
// answer can only come back that way.
func tunnelSourceAddress(luid winipcfg.LUID, ipv6 bool) (netip.Addr, error) {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if ipv6 {
		family = winipcfg.AddressFamily(windows.AF_INET6)
	}
	rows, err := winipcfg.GetUnicastIPAddressTable(family)
	if err != nil {
		return netip.Addr{}, err
	}
	for i := range rows {
		if rows[i].InterfaceLUID != luid || rows[i].DadState != winipcfg.DadStatePreferred {
			continue
		}
		addr := rows[i].Address.Addr()
		// A link-local source would need a scope, and a target through the tunnel is never link-local.
		if !addr.IsValid() || addr.IsLinkLocalUnicast() {
			continue
		}
		return addr.Unmap(), nil
	}
	return netip.Addr{}, errNoTunnelAddress
}
