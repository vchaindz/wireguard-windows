/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func TestProbeTargetChoice(t *testing.T) {
	config := func(dns []string, allowed ...[]string) *conf.Config {
		c := &conf.Config{}
		for _, d := range dns {
			c.Interface.DNS = append(c.Interface.DNS, netip.MustParseAddr(d))
		}
		for _, peer := range allowed {
			var p conf.Peer
			for _, a := range peer {
				p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix(a))
			}
			c.Peers = append(c.Peers, p)
		}
		return c
	}
	tests := []struct {
		name    string
		config  *conf.Config
		setting string
		want    string
	}{
		{"setting wins", config([]string{"10.0.0.53"}, []string{"10.0.0.1/32"}), "192.0.2.7", "192.0.2.7"},
		{"invalid setting falls back", config([]string{"10.0.0.53"}), "not an address", "10.0.0.53"},
		{"first DNS server", config([]string{"10.0.0.53", "10.0.0.54"}, []string{"10.0.0.1/32"}), "", "10.0.0.53"},
		{"IPv6 DNS server", config([]string{"fd00::53"}), "", "fd00::53"},
		{"single-host allowed IP", config(nil, []string{"0.0.0.0/0", "10.0.0.1/32"}), "", "10.0.0.1"},
		{"IPv6 single host", config(nil, []string{"::/0", "fd00::1/128"}), "", "fd00::1"},
		{"second peer", config(nil, []string{"10.1.0.0/16"}, []string{"10.2.0.9/32"}), "", "10.2.0.9"},
		{"networks only", config(nil, []string{"0.0.0.0/0", "10.0.0.0/24"}), "", ""},
		{"unspecified DNS skipped", config([]string{"0.0.0.0"}, []string{"10.0.0.1/32"}), "", "10.0.0.1"},
		{"mapped setting unmapped", config(nil), "::ffff:192.0.2.1", "192.0.2.1"},
		{"no configuration", nil, "", ""},
	}
	for _, test := range tests {
		got := probeTarget(test.config, test.setting)
		if test.want == "" {
			if got.IsValid() {
				t.Errorf("%s: got %v, want none", test.name, got)
			}
			continue
		}
		if got != netip.MustParseAddr(test.want) {
			t.Errorf("%s: got %v, want %s", test.name, got, test.want)
		}
	}
}

func TestProbeSettingsValidation(t *testing.T) {
	for _, target := range []string{"", "10.0.0.1", " 10.0.0.1 ", "fd00::1", "::ffff:10.0.0.1"} {
		if _, err := (TunnelSettings{Probe: true, ProbeTarget: target}).validate(); err != nil {
			t.Errorf("%q: %v", target, err)
		}
	}
	if settings, _ := (TunnelSettings{ProbeTarget: " ::ffff:10.0.0.1"}).validate(); settings.ProbeTarget != "10.0.0.1" {
		t.Errorf("not normalised: %q", settings.ProbeTarget)
	}
	for _, target := range []string{"example.com", "10.0.0.0/24", "10.0.0.1:53", "0.0.0.0", "::", "224.0.0.1", "fe80::1%eth0", `..\..\x`} {
		if _, err := (TunnelSettings{ProbeTarget: target}).validate(); err == nil {
			t.Errorf("%q accepted", target)
		}
	}
}

func TestProbeTally(t *testing.T) {
	var tally probeTally
	var sample TunnelSample
	tally.fill(&sample)
	if sample.Probed {
		t.Fatal("a sample without finished probes is marked probed")
	}
	tally.answered(10 * time.Millisecond)
	tally.unanswered()
	tally.answered(30 * time.Millisecond)
	tally.fill(&sample)
	want := TunnelSample{Probed: true, ProbesSent: 3, ProbesLost: 1, LatencyMicros: 20000, MaxLatencyMicros: 30000}
	if sample != want {
		t.Fatalf("got %+v, want %+v", sample, want)
	}
	var lost probeTally
	lost.unanswered()
	sample = TunnelSample{}
	lost.fill(&sample)
	if !sample.Probed || sample.ProbesLost != 1 || sample.LatencyMicros != 0 {
		t.Fatalf("all lost: got %+v", sample)
	}
}

// The layout of ICMP_ECHO_REPLY on this architecture, as the SDK defines it.
func TestProbeEchoReplyLayout(t *testing.T) {
	var reply icmpEchoReply
	want64 := map[string]uintptr{"Status": 4, "RoundTripTime": 8, "DataSize": 12, "Data": 16, "Options": 24, "size": 40}
	want32 := map[string]uintptr{"Status": 4, "RoundTripTime": 8, "DataSize": 12, "Data": 16, "Options": 20, "size": 28}
	want := want64
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = want32
	}
	got := map[string]uintptr{
		"Status":        unsafe.Offsetof(reply.Status),
		"RoundTripTime": unsafe.Offsetof(reply.RoundTripTime),
		"DataSize":      unsafe.Offsetof(reply.DataSize),
		"Data":          unsafe.Offsetof(reply.Data),
		"Options":       unsafe.Offsetof(reply.Options),
		"size":          unsafe.Sizeof(reply),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %d, want %d", k, got[k], v)
		}
	}
}

// Sends real echo requests over loopback, which checks the calls and the reply layouts against this machine's
// iphlpapi.dll. Loopback needs neither a tunnel nor administrator rights.
func TestProbeEchoLoopback(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "::1"} {
		addr := netip.MustParseAddr(a)
		h, err := openICMP(addr.Is6())
		if err != nil {
			t.Fatalf("%s: open: %v", a, err)
		}
		rtt, err := h.echo(addr, addr, probeTimeout)
		if err != nil {
			h.close()
			if addr.Is6() {
				t.Logf("%s: %v (IPv6 loopback may be unavailable)", a, err)
				continue
			}
			t.Fatalf("%s: echo: %v", a, err)
		}
		if rtt <= 0 || rtt > probeTimeout {
			t.Errorf("%s: implausible round trip %v", a, rtt)
		}
		t.Logf("%s: round trip %v", a, rtt)
		h.close()
	}
}

// Shows where the reply to ::1 put the address, which tells whether IPV6_ADDRESS_EX is packed. Status and
// RoundTripTime are at the same offsets either way; this only documents the finding.
func TestProbeEcho6ReplyAddress(t *testing.T) {
	h, err := openICMP(true)
	if err != nil {
		t.Skip(err)
	}
	defer h.close()
	var reply [icmpReplyBufferSize]byte
	data := icmpRequestData
	src := sockaddrInet6(netip.IPv6Loopback())
	dst := src
	r1, _, e1 := procIcmp6SendEcho2.Call(uintptr(h.handle), 0, 0, 0,
		uintptr(unsafe.Pointer(&src)), uintptr(unsafe.Pointer(&dst)),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(probeTimeout/time.Millisecond))
	if r1 == 0 {
		t.Skip(e1)
	}
	loopback := netip.IPv6Loopback().As16()
	switch {
	case bytes.Equal(reply[6:22], loopback[:]):
		t.Log("IPV6_ADDRESS_EX is packed: address at offset 6")
	case bytes.Equal(reply[8:24], loopback[:]):
		t.Log("IPV6_ADDRESS_EX is padded: address at offset 8")
	default:
		t.Errorf("reply address not found: % x", reply[:icmpv6EchoReplySize])
	}
	if status := uint32(reply[icmpv6EchoReplyStatusOffset]) | uint32(reply[icmpv6EchoReplyStatusOffset+1])<<8; status != ipSuccess {
		t.Errorf("status %d", status)
	}
}

func TestProbeEchoUnassignedSource(t *testing.T) {
	h, err := openICMP(false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	// 192.0.2.1 is reserved for documentation and assigned to no interface of this machine.
	_, err = h.echo(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1"), probeTimeout)
	if err == nil || err == errProbeLost {
		t.Fatalf("sending from an address this machine does not have: got %v, want an error meaning nothing was sent", err)
	}
	t.Logf("unassigned source: %v", err)
}

func TestProbeProberStops(t *testing.T) {
	prober := startTunnelProber("test")
	// A LUID that belongs to no interface: the request finds no source address and sends nothing.
	prober.request(netip.MustParseAddr("127.0.0.1"), 0)
	prober.close()
	select {
	case <-prober.done:
	case <-time.After(2 * probeTimeout):
		t.Fatal("prober did not stop")
	}
	if tally := prober.take(); tally.sent != 0 {
		t.Fatalf("sent %d probes without a source address", tally.sent)
	}
}
