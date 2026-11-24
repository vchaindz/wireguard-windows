/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
)

type fakeProbeTarget struct {
	sync.Mutex
	calls     [][]driver.Peer
	handshake bool
}

func (target *fakeProbeTarget) setKeepalives(peers []driver.Peer) error {
	target.Lock()
	defer target.Unlock()
	target.calls = append(target.calls, peers)
	return nil
}

func (target *fakeProbeTarget) anyPeerHasHandshake() bool {
	target.Lock()
	defer target.Unlock()
	return target.handshake
}

func (target *fakeProbeTarget) callCount() int {
	target.Lock()
	defer target.Unlock()
	return len(target.calls)
}

func (target *fakeProbeTarget) setHandshake() {
	target.Lock()
	defer target.Unlock()
	target.handshake = true
}

// peerWaitTestConfig has a peer with a keepalive configured, one without, and one without an endpoint.
func peerWaitTestConfig() *conf.Config {
	endpoint := conf.Endpoint{Host: "192.0.2.1", Port: 51820}
	return &conf.Config{Peers: []conf.Peer{
		{PublicKey: conf.Key{1}, Endpoint: endpoint, PersistentKeepalive: 10},
		{PublicKey: conf.Key{2}, Endpoint: endpoint},
		{PublicKey: conf.Key{3}},
	}}
}

func keepalivesByKey(peers []driver.Peer) map[byte]uint16 {
	result := make(map[byte]uint16)
	for _, peer := range peers {
		result[peer.PublicKey[0]] = peer.PersistentKeepalive
	}
	return result
}

func sameKeepalives(got, want map[byte]uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for key, keepalive := range want {
		if value, ok := got[key]; !ok || value != keepalive {
			return false
		}
	}
	return true
}

func TestKeepalivePeers(t *testing.T) {
	config := peerWaitTestConfig()
	for _, c := range []struct {
		name string
		step keepaliveStep
		want map[byte]uint16
	}{
		{"off", keepaliveOff, map[byte]uint16{1: 0, 2: 0}},
		{"probe", keepaliveProbe, map[byte]uint16{1: 10, 2: peerWaitProbeKeepalive}},
		{"restore", keepaliveRestore, map[byte]uint16{2: 0}},
	} {
		peers := keepalivePeers(config, c.step)
		if got := keepalivesByKey(peers); !sameKeepalives(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		// Any other flag would change more than the keepalive, or add a peer that is not there.
		want := driver.PeerHasPublicKey | driver.PeerHasPersistentKeepalive | driver.PeerUpdateOnly
		for _, peer := range peers {
			if peer.Flags != want {
				t.Errorf("%s: peer flags %#x, want %#x", c.name, peer.Flags, want)
			}
		}
	}
}

func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPeerWaiterProbesUntilAnswered(t *testing.T) {
	target := &fakeProbeTarget{}
	pw := startPeerWaiter(target, peerWaitTestConfig(), 40*time.Millisecond, 2*time.Millisecond)

	// The first probe happens at once: keepalive off, then on.
	waitUntil(t, "the first probe", func() bool { return target.callCount() >= 2 })
	// It is repeated after the probe interval.
	waitUntil(t, "the second probe", func() bool { return target.callCount() >= 4 })
	select {
	case <-pw.answered:
		t.Fatal("answered without a handshake")
	default:
	}

	target.setHandshake()
	select {
	case <-pw.answered:
	case <-time.After(5 * time.Second):
		t.Fatal("not answered after a handshake")
	}
	pw.cancel()

	target.Lock()
	defer target.Unlock()
	if n := len(target.calls); n%2 != 1 {
		t.Fatalf("%d keepalive updates: want pairs of probe steps followed by one restore", n)
	}
	for i, call := range target.calls[:len(target.calls)-1] {
		want := map[byte]uint16{1: 0, 2: 0}
		if i%2 == 1 {
			want = map[byte]uint16{1: 10, 2: peerWaitProbeKeepalive}
		}
		if got := keepalivesByKey(call); !sameKeepalives(got, want) {
			t.Errorf("update %d: got %v, want %v", i, got, want)
		}
	}
	if got := keepalivesByKey(target.calls[len(target.calls)-1]); !sameKeepalives(got, map[byte]uint16{2: 0}) {
		t.Errorf("restore: got %v, want only peer 2 set back to 0", got)
	}
}

func TestPeerWaiterCancel(t *testing.T) {
	target := &fakeProbeTarget{}
	pw := startPeerWaiter(target, peerWaitTestConfig(), 5*time.Millisecond, time.Millisecond)
	waitUntil(t, "the first probe", func() bool { return target.callCount() >= 2 })
	pw.cancel()
	calls := target.callCount()
	time.Sleep(30 * time.Millisecond)
	if after := target.callCount(); after != calls {
		t.Fatalf("%d keepalive updates after cancel", after-calls)
	}
	select {
	case <-pw.answered:
		t.Fatal("answered after cancel")
	default:
	}
}
