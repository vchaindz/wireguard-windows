/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"log"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TunnelHealth says whether a started tunnel actually has a working WireGuard session, which the service state alone
// cannot tell: the tunnel service is "running" as soon as the adapter is up, whether or not a peer ever answered.
type TunnelHealth int

const (
	// TunnelHealthUnknown means the tunnel is not started or has not been sampled yet.
	TunnelHealthUnknown TunnelHealth = iota
	// TunnelHealthUnverified means nothing has been sent to a peer that lacks a fresh handshake, so there is no evidence either way.
	TunnelHealthUnverified
	// TunnelHealthConnected means at least one peer completed a handshake recently.
	TunnelHealthConnected
	// TunnelHealthNoConnection means packets are being sent but no peer completes a handshake.
	TunnelHealthNoConnection
	// TunnelHealthWaitingForPeer is TunnelHealthNoConnection for a tunnel that has never had a handshake and
	// therefore has not applied its routes yet: the rest of the network is unaffected.
	TunnelHealthWaitingForPeer
	// TunnelHealthNoConnectionNetworkBlocked is TunnelHealthNoConnection for a tunnel that has taken over all
	// traffic: the machine has no usable network until the peer answers or the tunnel is deactivated.
	TunnelHealthNoConnectionNetworkBlocked
)

// IsNoConnection reports whether the health is one of the kinds of a peer not answering.
func (health TunnelHealth) IsNoConnection() bool {
	switch health {
	case TunnelHealthNoConnection, TunnelHealthWaitingForPeer, TunnelHealthNoConnectionNetworkBlocked:
		return true
	}
	return false
}

// refineTunnelHealth says what a missing connection means for the rest of the network. A tunnel that waits for
// its peer before routing has applied its routes exactly if it ever had a handshake.
func refineTunnelHealth(health TunnelHealth, everHandshake, waitsForPeerBeforeRouting, routesAllTraffic bool) TunnelHealth {
	if health != TunnelHealthNoConnection {
		return health
	}
	if waitsForPeerBeforeRouting && !everHandshake {
		return TunnelHealthWaitingForPeer
	}
	if routesAllTraffic {
		return TunnelHealthNoConnectionNetworkBlocked
	}
	return health
}

const (
	// Samples are taken every second while a window shows them, so that graphs move smoothly, and every five
	// seconds otherwise, which is enough for the connection check. The evaluator's rules are in terms of time,
	// not of samples, so they hold at either rate.
	healthSampleIntervalIdle    = 5 * time.Second
	healthSampleIntervalWatched = time.Second

	// A session is unusable 180 seconds after its handshake (REJECT_AFTER_TIME), so a younger handshake proves a live peer.
	healthHandshakeFresh = 180 * time.Second

	// Handshake initiations are retried every 5 seconds (REKEY_TIMEOUT). Sending for this long without a
	// handshake means several retries went unanswered.
	healthNoConnectionAfter = 20 * time.Second

	// Sessions are normally renewed every 120 seconds (REKEY_AFTER_TIME), and only under traffic. When another
	// device uses the same key, the server answers whichever device spoke last, the other one hears nothing and
	// renews after about 15 seconds, and so on in turns. Repeated renewals this close together are the symptom.
	healthConflictShortGap  = 60 * time.Second
	healthConflictWindow    = 5 * time.Minute
	healthConflictShortGaps = 3

	// A single early renewal means that the session was lost once and recovered, which is what an unreliable
	// path looks like before it happens often enough to suspect a second device.
	healthUnstableShortGaps = 1
)

type peerSample struct {
	publicKey     [32]byte
	lastHandshake time.Time // Zero if there has never been a handshake.
	txBytes       uint64
	rxBytes       uint64
}

type peerHealthState struct {
	seen          bool
	lastHandshake time.Time
	txBytes       uint64
	stalledSince  time.Time   // When we first saw packets being sent without a fresh handshake; zero if not stalled.
	handshakes    []time.Time // Distinct handshake times within healthConflictWindow.
}

// healthEvaluator turns successive samples of the driver's per-peer counters into a TunnelHealth and a
// duplicate-key suspicion. It keeps no reference to the driver, so that it can be tested with synthetic samples.
type healthEvaluator struct {
	peers map[[32]byte]*peerHealthState
	// newHandshakes is how many handshakes completed between the last two calls of observe. A handshake that a peer
	// already had when it was first seen is not counted, as it happened at some unknown time before.
	newHandshakes int
}

func newHealthEvaluator() *healthEvaluator {
	return &healthEvaluator{peers: make(map[[32]byte]*peerHealthState)}
}

// observe reports the tunnel's health, whether another device is suspected of using the same key, and, if not,
// whether the connection was lost and re-established recently.
func (e *healthEvaluator) observe(now time.Time, samples []peerSample) (health TunnelHealth, conflictSuspected, unstable bool) {
	present := make(map[[32]byte]bool, len(samples))
	anyConnected, anyNoConnection := false, false
	e.newHandshakes = 0
	for i := range samples {
		sample := &samples[i]
		present[sample.publicKey] = true
		state := e.peers[sample.publicKey]
		if state == nil {
			state = &peerHealthState{}
			e.peers[sample.publicKey] = state
		}

		if !sample.lastHandshake.IsZero() && sample.lastHandshake.After(state.lastHandshake) {
			state.handshakes = append(state.handshakes, sample.lastHandshake)
			if state.seen {
				e.newHandshakes++
			}
		}
		for len(state.handshakes) > 0 && now.Sub(state.handshakes[0]) > healthConflictWindow {
			state.handshakes = state.handshakes[1:]
		}
		shortGaps := 0
		for j := 1; j < len(state.handshakes); j++ {
			if state.handshakes[j].Sub(state.handshakes[j-1]) < healthConflictShortGap {
				shortGaps++
			}
		}
		if shortGaps >= healthConflictShortGaps {
			conflictSuspected = true
		} else if shortGaps >= healthUnstableShortGaps {
			unstable = true
		}

		if !sample.lastHandshake.IsZero() && now.Sub(sample.lastHandshake) < healthHandshakeFresh {
			state.stalledSince = time.Time{}
			anyConnected = true
		} else {
			// Without a fresh handshake, bytes can only be sent as handshake initiations, so a growing counter
			// means the driver is trying to reach the peer. On the first sample of a peer that has never had a
			// handshake, any sent bytes are such attempts.
			var attempting bool
			if state.seen {
				attempting = sample.txBytes > state.txBytes
			} else {
				attempting = sample.lastHandshake.IsZero() && sample.txBytes > 0
			}
			if attempting && state.stalledSince.IsZero() {
				state.stalledSince = now
			}
			// Once stalled, stay so until a handshake succeeds: the driver gives up retrying when
			// applications stop sending, which does not mean that the peer became reachable.
			if !state.stalledSince.IsZero() && now.Sub(state.stalledSince) >= healthNoConnectionAfter {
				anyNoConnection = true
			}
		}

		state.seen = true
		state.lastHandshake = sample.lastHandshake
		state.txBytes = sample.txBytes
	}
	for key := range e.peers {
		if !present[key] {
			delete(e.peers, key)
		}
	}

	if conflictSuspected {
		unstable = false
	}
	switch {
	case anyConnected:
		health = TunnelHealthConnected
	case anyNoConnection:
		health = TunnelHealthNoConnection
	default:
		health = TunnelHealthUnverified
	}
	return
}

type tunnelHealthMonitor struct {
	stop chan struct{}
	done chan struct{}
}

type tunnelHealthStatus struct {
	health            TunnelHealth
	conflictSuspected bool
	unstable          bool
}

// Both maps are protected by trackedTunnelsLock.
var (
	tunnelHealthMonitors = make(map[string]*tunnelHealthMonitor)
	trackedTunnelsHealth = make(map[string]tunnelHealthStatus)
)

func trackedTunnelHealth(tunnelName string) (health TunnelHealth, conflictSuspected, unstable bool) {
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	status := trackedTunnelsHealth[tunnelName]
	return status.health, status.conflictSuspected, status.unstable
}

func startTunnelHealthMonitor(tunnelName string) {
	monitor := &tunnelHealthMonitor{stop: make(chan struct{}), done: make(chan struct{})}
	trackedTunnelsLock.Lock()
	if _, found := tunnelHealthMonitors[tunnelName]; found {
		trackedTunnelsLock.Unlock()
		return
	}
	tunnelHealthMonitors[tunnelName] = monitor
	trackedTunnelsSamples[tunnelName] = newSampleHistory()
	trackedTunnelsLock.Unlock()
	withTunnelMetrics(tunnelName, func(r *metricsRecorder) { r.started(time.Now()) })
	go monitor.run(tunnelName)
}

// stopTunnelHealthMonitor returns only after the monitor has finished, so that it cannot reopen the driver
// adapter after the caller releases it.
func stopTunnelHealthMonitor(tunnelName string) {
	trackedTunnelsLock.Lock()
	monitor := tunnelHealthMonitors[tunnelName]
	delete(tunnelHealthMonitors, tunnelName)
	delete(trackedTunnelsHealth, tunnelName)
	delete(trackedTunnelsSamples, tunnelName)
	trackedTunnelsLock.Unlock()
	if monitor == nil {
		return
	}
	close(monitor.stop)
	<-monitor.done
	now := time.Now()
	withTunnelMetrics(tunnelName, func(r *metricsRecorder) { r.stopped(now) })
	historyStopped(tunnelName, now)
}

// Watchers are the connected UIs that currently show live data. While there is one, tunnels are sampled every
// second. sampleWatchersChanged is closed and replaced whenever that switches, so that waiting monitors pick up
// the new rate at once instead of after their current five seconds.
var (
	sampleWatchersLock    sync.Mutex
	sampleWatchers        int
	sampleWatchersChanged = make(chan struct{})
)

func addSampleWatcher(delta int) {
	sampleWatchersLock.Lock()
	defer sampleWatchersLock.Unlock()
	before := sampleWatchers > 0
	sampleWatchers = max(sampleWatchers+delta, 0)
	if (sampleWatchers > 0) != before {
		close(sampleWatchersChanged)
		sampleWatchersChanged = make(chan struct{})
	}
}

func sampleInterval() (time.Duration, <-chan struct{}) {
	sampleWatchersLock.Lock()
	defer sampleWatchersLock.Unlock()
	if sampleWatchers > 0 {
		return healthSampleIntervalWatched, sampleWatchersChanged
	}
	return healthSampleIntervalIdle, sampleWatchersChanged
}

// probeState is what a monitor knows about measuring its tunnel's connection quality.
type probeState struct {
	initialized bool
	settings    TunnelSettings
	allowed     bool
	target      netip.Addr
	prober      *tunnelProber
}

// update starts or stops the prober when the settings or the policy changed since the last sample, so that
// switching measurement on or off takes effect on a running tunnel.
func (p *probeState) update(tunnelName string) {
	settings, allowed := loadTunnelSettings(tunnelName), probingAllowed()
	if p.initialized && settings == p.settings && allowed == p.allowed {
		return
	}
	wasProbing, oldTarget := p.prober != nil, p.target
	p.initialized, p.settings, p.allowed = true, settings, allowed
	p.target = netip.Addr{}
	if settings.Probe && allowed {
		// The configuration is read again, so that a tunnel edited while running uses its new addresses.
		config, _ := conf.LoadFromName(tunnelName)
		p.target = probeTarget(config, settings.ProbeTarget)
	}
	if p.prober != nil && p.target != oldTarget {
		p.prober.close()
		p.prober = nil
	}
	switch {
	case p.target.IsValid() && p.prober == nil:
		p.prober = startTunnelProber(tunnelName)
		log.Printf("[%s] Connection quality: measuring latency and loss to %v", tunnelName, p.target)
	case p.target.IsValid():
	case settings.Probe && !allowed:
		log.Printf("[%s] Connection quality: measuring is disabled by policy", tunnelName)
	case settings.Probe:
		log.Printf("[%s] Warning: connection quality: there is no address to measure; set one in the tunnel settings", tunnelName)
	case wasProbing:
		log.Printf("[%s] Connection quality: measuring stopped", tunnelName)
	}
}

func (p *probeState) close() {
	if p.prober != nil {
		p.prober.close()
		p.prober = nil
	}
}

func (monitor *tunnelHealthMonitor) run(tunnelName string) {
	defer close(monitor.done)
	evaluator := newHealthEvaluator()
	var waitsForPeerBeforeRouting, routesAllTraffic bool
	var endpoint string
	var configuredListenPort uint16
	if config, err := conf.LoadFromName(tunnelName); err == nil {
		configuredListenPort = config.Interface.ListenPort
		waitsForPeerBeforeRouting = config.WaitsForPeerBeforeRouting()
		routesAllTraffic = config.RoutesAllTraffic()
		if len(config.Peers) > 0 && !config.Peers[0].Endpoint.IsEmpty() {
			endpoint = config.Peers[0].Endpoint.String()
		}
	}
	var probe probeState
	defer probe.close()
	var last tunnelHealthStatus
	for {
		select {
		case <-monitor.stop:
			return
		default:
		}
		probe.update(tunnelName)
		if samples, counters, luid, listenPort, err := sampleTunnelPeers(tunnelName); err == nil {
			var status tunnelHealthStatus
			now := time.Now()
			status.health, status.conflictSuspected, status.unstable = evaluator.observe(now, samples)
			everHandshake := false
			for i := range samples {
				if !samples[i].lastHandshake.IsZero() {
					everHandshake = true
					break
				}
			}
			status.health = refineTunnelHealth(status.health, everHandshake, waitsForPeerBeforeRouting, routesAllTraffic)
			withTunnelMetrics(tunnelName, func(r *metricsRecorder) {
				r.observed(now, status.health, counters)
				r.listenPort(configuredListenPort, listenPort)
			})

			// Each sample carries the probes that finished since the previous one, and then the next probe is
			// sent, so that it has until the next sample to be answered.
			tunnelSample := TunnelSample{Time: now, Health: status.health, Handshakes: uint8(min(evaluator.newHandshakes, 0xff)),
				ConflictSuspected: status.conflictSuspected, Unstable: status.unstable}
			for i := range samples {
				tunnelSample.RxBytes += samples[i].rxBytes
				tunnelSample.TxBytes += samples[i].txBytes
			}
			if probe.prober != nil {
				probe.prober.take().fill(&tunnelSample)
			}
			trackedTunnelsLock.Lock()
			current := tunnelHealthMonitors[tunnelName] == monitor
			if current {
				if history := trackedTunnelsSamples[tunnelName]; history != nil {
					history.add(tunnelSample)
				}
				if status != last {
					trackedTunnelsHealth[tunnelName] = status
				}
			}
			trackedTunnelsLock.Unlock()
			if !current {
				return
			}
			if probe.prober != nil {
				probe.prober.request(probe.target, luid)
			}
			// After the probe is sent, so that writing the history once a minute does not delay it.
			historyObserve(tunnelName, endpoint, now, tunnelSample.RxBytes, tunnelSample.TxBytes, status.health)

			if status != last {
				if status.health != last.health {
					switch status.health {
					case TunnelHealthConnected:
						log.Printf("[%s] Connection check: handshake completed, tunnel is connected", tunnelName)
					case TunnelHealthNoConnection:
						log.Printf("[%s] Warning: connection check: packets are being sent but no peer completes a handshake", tunnelName)
					case TunnelHealthWaitingForPeer:
						log.Printf("[%s] Warning: connection check: no peer answers; routes have not been applied, so the rest of the network is unaffected", tunnelName)
					case TunnelHealthNoConnectionNetworkBlocked:
						log.Printf("[%s] Error: connection check: no peer completes a handshake, and this tunnel takes over all traffic, so the network is cut off", tunnelName)
					case TunnelHealthUnverified:
						log.Printf("[%s] Connection check: no recent handshake, connection is not verified", tunnelName)
					}
				}
				if status.conflictSuspected != last.conflictSuspected {
					if status.conflictSuspected {
						log.Printf("[%s] Warning: connection check: handshakes are repeating unusually often; another device is probably using the same private key", tunnelName)
					} else {
						log.Printf("[%s] Connection check: handshake rate is back to normal", tunnelName)
					}
				}
				if status.unstable && !last.unstable {
					log.Printf("[%s] Warning: connection check: the session was lost and re-established; the connection is unstable", tunnelName)
				}
				IPCServerNotifyTunnelHealth(tunnelName, status.health, status.conflictSuspected, status.unstable)
				last = status
			}
		}
		interval, changed := sampleInterval()
		timer := time.NewTimer(interval)
		select {
		case <-monitor.stop:
			timer.Stop()
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// sampleTunnelPeers reads the state of the peers of a started tunnel, the LUID of its network interface, the port
// it listens on and, if they can be had, the error counters of that interface.
func sampleTunnelPeers(tunnelName string) ([]peerSample, *interfaceCounters, winipcfg.LUID, uint16, error) {
	driverAdapter, err := findDriverAdapter(tunnelName)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	config, err := driverAdapter.Configuration()
	if err != nil {
		driverAdapter.Unlock()
		releaseDriverAdapter(tunnelName)
		return nil, nil, 0, 0, err
	}
	luid := driverAdapter.LUID()
	driverAdapter.Unlock()
	var counters *interfaceCounters
	if row, err := luid.Interface(); err == nil {
		counters = &interfaceCounters{row.InErrors, row.OutErrors, row.InDiscards, row.OutDiscards}
	}
	samples := make([]peerSample, 0, config.PeerCount)
	peer := config.FirstPeer()
	for i := uint32(0); i < config.PeerCount; i++ {
		if i > 0 {
			peer = peer.NextPeer()
		}
		sample := peerSample{publicKey: peer.PublicKey, txBytes: peer.TxBytes, rxBytes: peer.RxBytes}
		if peer.LastHandshake != 0 {
			// LastHandshake is a FILETIME: 100ns units since 1601.
			sample.lastHandshake = time.Unix(0, int64((peer.LastHandshake-116444736000000000)*100))
		}
		samples = append(samples, sample)
	}
	var listenPort uint16
	if config.Flags&driver.InterfaceHasListenPort != 0 {
		listenPort = config.ListenPort
	}
	return samples, counters, luid, listenPort, nil
}
