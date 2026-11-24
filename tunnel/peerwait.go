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
	// keepalive on makes the driver send a keepalive at once, which starts one.
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

func waitForPeer(adapter *driver.Adapter, config *conf.Config) *peerWaiter {
	pw := &peerWaiter{
		answered: make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(pw.done)
		probe := time.NewTicker(peerWaitProbeInterval)
		defer probe.Stop()
		poll := time.NewTicker(peerWaitPollInterval)
		defer poll.Stop()
		probePeers(adapter, config)
		for {
			select {
			case <-pw.stop:
				return
			case <-probe.C:
				probePeers(adapter, config)
			case <-poll.C:
				if !anyPeerHasHandshake(adapter) {
					continue
				}
				// Put back the configured keepalive of the peers that have none of their own.
				err := setPeerKeepalives(adapter, config, func(peer *conf.Peer) (uint16, bool) {
					return 0, peer.PersistentKeepalive == 0
				})
				if err != nil {
					log.Printf("Unable to restore persistent keepalive after probing: %v", err)
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

// probePeers makes the driver start a handshake with every peer that has an endpoint. The driver sends a
// keepalive only when persistent keepalive goes from off to on, hence the two steps.
func probePeers(adapter *driver.Adapter, config *conf.Config) {
	err := setPeerKeepalives(adapter, config, func(peer *conf.Peer) (uint16, bool) {
		return 0, true
	})
	if err == nil {
		err = setPeerKeepalives(adapter, config, func(peer *conf.Peer) (uint16, bool) {
			if peer.PersistentKeepalive != 0 {
				return peer.PersistentKeepalive, true
			}
			return peerWaitProbeKeepalive, true
		})
	}
	if err != nil {
		log.Printf("Unable to probe peers: %v", err)
	}
}

// setPeerKeepalives changes only the persistent keepalive of the peers that have an endpoint and that the given
// function selects, leaving keys, endpoints and allowed IPs as they are.
func setPeerKeepalives(adapter *driver.Adapter, config *conf.Config, keepalive func(peer *conf.Peer) (uint16, bool)) error {
	var peers []driver.Peer
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.Endpoint.IsEmpty() {
			continue
		}
		value, ok := keepalive(peer)
		if !ok {
			continue
		}
		peers = append(peers, driver.Peer{
			Flags:               driver.PeerHasPublicKey | driver.PeerHasPersistentKeepalive | driver.PeerUpdateOnly,
			PublicKey:           peer.PublicKey,
			PersistentKeepalive: value,
		})
	}
	if len(peers) == 0 {
		return nil
	}
	var builder driver.ConfigBuilder
	builder.AppendInterface(&driver.Interface{PeerCount: uint32(len(peers))})
	for i := range peers {
		builder.AppendPeer(&peers[i])
	}
	return adapter.SetConfiguration(builder.Interface())
}

func anyPeerHasHandshake(adapter *driver.Adapter) bool {
	config, err := adapter.Configuration()
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
