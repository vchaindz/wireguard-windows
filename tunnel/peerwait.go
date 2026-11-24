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
)

// peerWaiter watches a freshly started adapter until some peer completes a handshake, so that routes, DNS and
// firewall rules are only applied to a tunnel that has somebody at the other end.
type peerWaiter struct {
	answered chan struct{}
	stop     chan struct{}
	done     chan struct{}
}

// A peerProbeTarget is what the waiter needs from the adapter. Tests supply a fake one.
type peerProbeTarget interface {
	// setKeepalives changes only the persistent keepalive of the given peers.
	setKeepalives(peers []driver.Peer) error
	anyPeerHasHandshake() bool
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
	return startPeerWaiter(adapterProbeTarget{adapter}, config, peerWaitProbeInterval, peerWaitPollInterval)
}

func startPeerWaiter(target peerProbeTarget, config *conf.Config, probeInterval, pollInterval time.Duration) *peerWaiter {
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
		probePeers()
		for {
			select {
			case <-pw.stop:
				return
			case <-probe.C:
				probePeers()
			case <-poll.C:
				if !target.anyPeerHasHandshake() {
					continue
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
