/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"log"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
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
	healthSampleInterval = 5 * time.Second

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
}

func newHealthEvaluator() *healthEvaluator {
	return &healthEvaluator{peers: make(map[[32]byte]*peerHealthState)}
}

// observe reports the tunnel's health, whether another device is suspected of using the same key, and, if not,
// whether the connection was lost and re-established recently.
func (e *healthEvaluator) observe(now time.Time, samples []peerSample) (health TunnelHealth, conflictSuspected, unstable bool) {
	present := make(map[[32]byte]bool, len(samples))
	anyConnected, anyNoConnection := false, false
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
	trackedTunnelsLock.Unlock()
	go monitor.run(tunnelName)
}

// stopTunnelHealthMonitor returns only after the monitor has finished, so that it cannot reopen the driver
// adapter after the caller releases it.
func stopTunnelHealthMonitor(tunnelName string) {
	trackedTunnelsLock.Lock()
	monitor := tunnelHealthMonitors[tunnelName]
	delete(tunnelHealthMonitors, tunnelName)
	delete(trackedTunnelsHealth, tunnelName)
	trackedTunnelsLock.Unlock()
	if monitor == nil {
		return
	}
	close(monitor.stop)
	<-monitor.done
}

func (monitor *tunnelHealthMonitor) run(tunnelName string) {
	defer close(monitor.done)
	evaluator := newHealthEvaluator()
	var waitsForPeerBeforeRouting, routesAllTraffic bool
	if config, err := conf.LoadFromName(tunnelName); err == nil {
		waitsForPeerBeforeRouting = config.WaitsForPeerBeforeRouting()
		routesAllTraffic = config.RoutesAllTraffic()
	}
	ticker := time.NewTicker(healthSampleInterval)
	defer ticker.Stop()
	var last tunnelHealthStatus
	for {
		select {
		case <-monitor.stop:
			return
		default:
		}
		if samples, err := sampleTunnelPeers(tunnelName); err == nil {
			var status tunnelHealthStatus
			status.health, status.conflictSuspected, status.unstable = evaluator.observe(time.Now(), samples)
			everHandshake := false
			for i := range samples {
				if !samples[i].lastHandshake.IsZero() {
					everHandshake = true
					break
				}
			}
			status.health = refineTunnelHealth(status.health, everHandshake, waitsForPeerBeforeRouting, routesAllTraffic)
			if status != last {
				trackedTunnelsLock.Lock()
				current := tunnelHealthMonitors[tunnelName] == monitor
				if current {
					trackedTunnelsHealth[tunnelName] = status
				}
				trackedTunnelsLock.Unlock()
				if !current {
					return
				}
				if status.health != last.health {
					switch status.health {
					case TunnelHealthConnected:
						log.Printf("[%s] Connection check: handshake completed, tunnel is connected", tunnelName)
					case TunnelHealthNoConnection:
						log.Printf("[%s] Connection check: packets are being sent but no peer completes a handshake", tunnelName)
					case TunnelHealthWaitingForPeer:
						log.Printf("[%s] Connection check: no peer answers; routes have not been applied, so the rest of the network is unaffected", tunnelName)
					case TunnelHealthNoConnectionNetworkBlocked:
						log.Printf("[%s] Connection check: no peer completes a handshake, and this tunnel takes over all traffic, so the network is cut off", tunnelName)
					case TunnelHealthUnverified:
						log.Printf("[%s] Connection check: no recent handshake, connection is not verified", tunnelName)
					}
				}
				if status.conflictSuspected != last.conflictSuspected {
					if status.conflictSuspected {
						log.Printf("[%s] Connection check: handshakes are repeating unusually often; another device is probably using the same private key", tunnelName)
					} else {
						log.Printf("[%s] Connection check: handshake rate is back to normal", tunnelName)
					}
				}
				if status.unstable && !last.unstable {
					log.Printf("[%s] Connection check: the session was lost and re-established; the connection is unstable", tunnelName)
				}
				IPCServerNotifyTunnelHealth(tunnelName, status.health, status.conflictSuspected, status.unstable)
				last = status
			}
		}
		select {
		case <-monitor.stop:
			return
		case <-ticker.C:
		}
	}
}

func sampleTunnelPeers(tunnelName string) ([]peerSample, error) {
	driverAdapter, err := findDriverAdapter(tunnelName)
	if err != nil {
		return nil, err
	}
	config, err := driverAdapter.Configuration()
	if err != nil {
		driverAdapter.Unlock()
		releaseDriverAdapter(tunnelName)
		return nil, err
	}
	driverAdapter.Unlock()
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
	return samples, nil
}
