/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
)

const (
	// Without routes nothing enters the tunnel, so nothing would ever start a handshake. Turning persistent
	// keepalive on makes the driver send a keepalive at once, which starts one. This is the value used for
	// peers that have no keepalive configured.
	peerWaitProbeKeepalive = 25

	// The driver retries a handshake every 5 seconds for 90 seconds (REKEY_ATTEMPT_TIME) and then gives up until
	// there is something new to send, so it has to be prodded again after that.
	peerWaitProbeInterval = 95 * time.Second

	peerWaitPollInterval = time.Second

	// A fixed listen port can be one that replies never arrive on, for instance because the router or another
	// device behind it uses the same port for its own WireGuard. After this long without an answer the waiter
	// tries from a port that the system picks.
	peerWaitPortFallbackAfter = 15 * time.Second
)

// peerWaiter watches a freshly started adapter until some peer completes a handshake, so that routes, DNS and
// firewall rules are only applied to a tunnel that has somebody at the other end.
type peerWaiter struct {
	answered chan struct{}
	stop     chan struct{}
	done     chan struct{}
}

// portFallbackDelay returns how long to wait for an answer on the configured listen port before trying another
// one, or zero if the port is to be kept: none is configured, or the administrator wants it kept.
func portFallbackDelay(config *conf.Config) time.Duration {
	if config.Interface.ListenPort == 0 || conf.AdminBool("DisableListenPortFallback") {
		return 0
	}
	return peerWaitPortFallbackAfter
}

// A peerProbeTarget is what the waiter needs from the adapter. Tests supply a fake one.
type peerProbeTarget interface {
	// setKeepalives changes only the persistent keepalive of the given peers.
	setKeepalives(peers []driver.Peer) error
	anyPeerHasHandshake() bool
	// useRandomPort makes the adapter listen on a port that the system picks.
	useRandomPort() error
}

type keepaliveStep int

const (
	// keepaliveOff and keepaliveProbe together make the driver start a handshake: it sends a keepalive only
	// when persistent keepalive goes from off to on.
	keepaliveOff keepaliveStep = iota
	keepaliveProbe
	// keepaliveRestore puts back the configuration of the peers that have no keepalive configured.
	keepaliveRestore
)

// keepalivePeers returns the keepalive updates of one step for the peers that have an endpoint. Peers without
// one cannot be contacted first, so they are left alone.
func keepalivePeers(config *conf.Config, step keepaliveStep) []driver.Peer {
	var peers []driver.Peer
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.Endpoint.IsEmpty() {
			continue
		}
		var keepalive uint16
		switch step {
		case keepaliveProbe:
			keepalive = peer.PersistentKeepalive
			if keepalive == 0 {
				keepalive = peerWaitProbeKeepalive
			}
		case keepaliveRestore:
			if peer.PersistentKeepalive != 0 {
				continue
			}
		}
		peers = append(peers, driver.Peer{
			Flags:               driver.PeerHasPublicKey | driver.PeerHasPersistentKeepalive | driver.PeerUpdateOnly,
			PublicKey:           peer.PublicKey,
			PersistentKeepalive: keepalive,
		})
	}
	return peers
}

func waitForPeer(adapter *driver.Adapter, config *conf.Config) *peerWaiter {
	return startPeerWaiter(adapterProbeTarget{adapter}, config, peerWaitProbeInterval, peerWaitPollInterval, portFallbackDelay(config))
}

// startPeerWaiter probes the peers until one answers. If portFallbackAfter is not zero and nobody has answered on
// the configured listen port by then, it switches to a random port and clears the port in config, so that
// whatever applies the configuration again later does not go back to the port that did not work. The caller must
// not use config until the waiter has answered or has been cancelled.
func startPeerWaiter(target peerProbeTarget, config *conf.Config, probeInterval, pollInterval, portFallbackAfter time.Duration) *peerWaiter {
	pw := &peerWaiter{
		answered: make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	probePeers := func() {
		err := target.setKeepalives(keepalivePeers(config, keepaliveOff))
		if err == nil {
			err = target.setKeepalives(keepalivePeers(config, keepaliveProbe))
		}
		if err != nil {
			log.Printf("Warning: unable to probe peers: %v", err)
		}
	}
	go func() {
		defer close(pw.done)
		probe := time.NewTicker(probeInterval)
		defer probe.Stop()
		poll := time.NewTicker(pollInterval)
		defer poll.Stop()
		var portFallback <-chan time.Time
		if portFallbackAfter > 0 && config.Interface.ListenPort != 0 {
			timer := time.NewTimer(portFallbackAfter)
			defer timer.Stop()
			portFallback = timer.C
		}
		var replacedPort uint16
		probePeers()
		for {
			select {
			case <-pw.stop:
				return
			case <-probe.C:
				probePeers()
			case <-portFallback:
				portFallback = nil
				if target.anyPeerHasHandshake() {
					continue
				}
				port := config.Interface.ListenPort
				if err := target.useRandomPort(); err != nil {
					log.Printf("Warning: no reply has arrived on listen port %d, and switching to a random port failed: %v", port, err)
					continue
				}
				log.Printf("Warning: no reply has arrived on listen port %d after %v, trying from a random port instead", port, portFallbackAfter)
				replacedPort = port
				config.Interface.ListenPort = 0
				probePeers()
			case <-poll.C:
				if !target.anyPeerHasHandshake() {
					continue
				}
				if replacedPort != 0 {
					log.Printf("Warning: the peer answered once a random port was used instead of listen port %d. That port does not seem to work on this network: the router or another device may be using it. Remove ListenPort from the configuration or choose another port.", replacedPort)
				}
				if err := target.setKeepalives(keepalivePeers(config, keepaliveRestore)); err != nil {
					log.Printf("Warning: unable to restore persistent keepalive after probing: %v", err)
				}
				pw.answered <- struct{}{}
				return
			}
		}
	}()
	return pw
}

// cancel returns only after the waiter has stopped using the adapter.
func (pw *peerWaiter) cancel() {
	close(pw.stop)
	<-pw.done
}

type adapterProbeTarget struct {
	adapter *driver.Adapter
}

// setKeepalives leaves keys, endpoints and allowed IPs of the peers as they are.
func (target adapterProbeTarget) setKeepalives(peers []driver.Peer) error {
	if len(peers) == 0 {
		return nil
	}
	var builder driver.ConfigBuilder
	builder.AppendInterface(&driver.Interface{PeerCount: uint32(len(peers))})
	for i := range peers {
		builder.AppendPeer(&peers[i])
	}
	return target.adapter.SetConfiguration(builder.Interface())
}

// useRandomPort leaves the key and the peers as they are. The driver takes a listen port of zero to mean any.
func (target adapterProbeTarget) useRandomPort() error {
	var builder driver.ConfigBuilder
	builder.AppendInterface(&driver.Interface{Flags: driver.InterfaceHasListenPort})
	return target.adapter.SetConfiguration(builder.Interface())
}

func (target adapterProbeTarget) anyPeerHasHandshake() bool {
	config, err := target.adapter.Configuration()
	if err != nil {
		return false
	}
	peer := config.FirstPeer()
	for i := uint32(0); i < config.PeerCount; i++ {
		if i > 0 {
			peer = peer.NextPeer()
		}
		if peer.LastHandshake != 0 {
			return true
		}
	}
	return false
}
