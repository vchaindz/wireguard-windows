/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"testing"
	"time"
)

var healthTestStart = time.Unix(1700000000, 0)

func at(seconds int) time.Time {
	return healthTestStart.Add(time.Duration(seconds) * time.Second)
}

func one(lastHandshake time.Time, tx, rx uint64) []peerSample {
	return []peerSample{{publicKey: [32]byte{1}, lastHandshake: lastHandshake, txBytes: tx, rxBytes: rx}}
}

func TestHealthIdleIsUnverified(t *testing.T) {
	e := newHealthEvaluator()
	for s := 0; s <= 300; s += 5 {
		if health, conflict, unstable := e.observe(at(s), one(time.Time{}, 0, 0)); health != TunnelHealthUnverified || conflict || unstable {
			t.Fatalf("at %ds: got %v, %v", s, health, conflict)
		}
	}
}

func TestHealthNoHandshakeBecomesNoConnection(t *testing.T) {
	e := newHealthEvaluator()
	e.observe(at(0), one(time.Time{}, 0, 0))
	for s := 5; s <= 60; s += 5 {
		health, _, _ := e.observe(at(s), one(time.Time{}, uint64(s)*148/5, 0))
		want := TunnelHealthUnverified
		if s >= 25 {
			want = TunnelHealthNoConnection
		}
		if health != want {
			t.Fatalf("at %ds: got %v, want %v", s, health, want)
		}
	}
	// It stays so when sending stops, and recovers on a handshake.
	if health, _, _ := e.observe(at(300), one(time.Time{}, 1776, 0)); health != TunnelHealthNoConnection {
		t.Fatalf("after sending stopped: got %v", health)
	}
	if health, _, _ := e.observe(at(305), one(at(303), 2000, 92)); health != TunnelHealthConnected {
		t.Fatalf("after handshake: got %v", health)
	}
}

func TestHealthAttemptsBeforeFirstSample(t *testing.T) {
	e := newHealthEvaluator()
	e.observe(at(0), one(time.Time{}, 444, 0))
	if health, _, _ := e.observe(at(20), one(time.Time{}, 444, 0)); health != TunnelHealthNoConnection {
		t.Fatalf("got %v", health)
	}
}

func TestHealthHandshakeAgeing(t *testing.T) {
	e := newHealthEvaluator()
	if health, _, _ := e.observe(at(10), one(at(5), 1000, 1000)); health != TunnelHealthConnected {
		t.Fatalf("fresh handshake: got %v", health)
	}
	// Idle after the handshake aged out: nothing to say.
	if health, _, _ := e.observe(at(200), one(at(5), 1000, 1000)); health != TunnelHealthUnverified {
		t.Fatalf("aged, idle: got %v", health)
	}
	// Sending again without getting a new handshake.
	e.observe(at(205), one(at(5), 1148, 1000))
	if health, _, _ := e.observe(at(225), one(at(5), 1740, 1000)); health != TunnelHealthNoConnection {
		t.Fatalf("aged, sending: got %v", health)
	}
}

func TestHealthAnyConnectedPeerWins(t *testing.T) {
	e := newHealthEvaluator()
	samples := func(s int) []peerSample {
		return []peerSample{
			{publicKey: [32]byte{1}, txBytes: uint64(s) * 30},
			{publicKey: [32]byte{2}, lastHandshake: at(0), txBytes: 500, rxBytes: 500},
		}
	}
	for s := 0; s <= 60; s += 5 {
		if health, _, _ := e.observe(at(s), samples(s)); health != TunnelHealthConnected {
			t.Fatalf("at %ds: got %v", s, health)
		}
	}
}

func TestHealthRefine(t *testing.T) {
	for _, c := range []struct {
		health                                 TunnelHealth
		everHandshake, waits, routesAllTraffic bool
		want                                   TunnelHealth
	}{
		{TunnelHealthConnected, true, true, true, TunnelHealthConnected},
		{TunnelHealthUnverified, false, true, true, TunnelHealthUnverified},
		{TunnelHealthNoConnection, false, true, true, TunnelHealthWaitingForPeer},
		{TunnelHealthNoConnection, false, true, false, TunnelHealthWaitingForPeer},
		{TunnelHealthNoConnection, true, true, true, TunnelHealthNoConnectionNetworkBlocked},
		{TunnelHealthNoConnection, false, false, true, TunnelHealthNoConnectionNetworkBlocked},
		{TunnelHealthNoConnection, true, true, false, TunnelHealthNoConnection},
		{TunnelHealthNoConnection, false, false, false, TunnelHealthNoConnection},
	} {
		if got := refineTunnelHealth(c.health, c.everHandshake, c.waits, c.routesAllTraffic); got != c.want {
			t.Errorf("refine(%v, %v, %v, %v) = %v, want %v", c.health, c.everHandshake, c.waits, c.routesAllTraffic, got, c.want)
		}
		if c.want.IsNoConnection() != (c.health == TunnelHealthNoConnection) {
			t.Errorf("IsNoConnection(%v) is wrong", c.want)
		}
	}
}

func TestHealthConflict(t *testing.T) {
	e := newHealthEvaluator()
	handshake := at(0)
	flaggedAt, unstableAt := -1, -1
	for s := 0; s <= 120; s += 5 {
		if s%20 == 0 {
			handshake = at(s)
		}
		_, conflict, unstable := e.observe(at(s), one(handshake, uint64(s)*100, uint64(s)*50))
		if conflict && unstable {
			t.Fatalf("at %ds: both conflict and unstable", s)
		}
		if unstable && unstableAt < 0 {
			unstableAt = s
		}
		if conflict && flaggedAt < 0 {
			flaggedAt = s
		}
	}
	if unstableAt != 20 {
		t.Fatalf("unstable at %ds, want 20s (second handshake)", unstableAt)
	}
	if flaggedAt != 60 {
		t.Fatalf("flagged at %ds, want 60s (fourth handshake)", flaggedAt)
	}
	// The other device goes away: normal two-minute renewals clear the flag once the window has passed.
	cleared := false
	for s := 125; s <= 600; s += 5 {
		if s%120 == 0 {
			handshake = at(s)
		}
		_, conflict, unstable := e.observe(at(s), one(handshake, uint64(s)*100, uint64(s)*50))
		if !conflict && !unstable {
			cleared = true
		} else if cleared {
			t.Fatalf("flag came back at %ds", s)
		}
	}
	if !cleared {
		t.Fatal("flag never cleared")
	}
}

func TestHealthNormalRekeyIsNoConflict(t *testing.T) {
	e := newHealthEvaluator()
	handshake := at(0)
	for s := 0; s <= 1800; s += 5 {
		if s%120 == 0 {
			handshake = at(s)
		}
		if health, conflict, unstable := e.observe(at(s), one(handshake, uint64(s)*100, uint64(s)*50)); conflict || unstable || health != TunnelHealthConnected {
			t.Fatalf("at %ds: got %v, %v, %v", s, health, conflict, unstable)
		}
	}
}

// At one sample per second, as while a window is open, the evaluator must reach the same verdicts at the same
// times: its rules are in terms of elapsed time, and a counter that did not grow since the last sample must not
// be taken as the peer having answered.
func TestHealthOneSecondSamplesNoConnection(t *testing.T) {
	e := newHealthEvaluator()
	initiations := 0
	for s := 0; s <= 60; s++ {
		// Handshake initiations every 5 seconds, starting at 1 s, so most samples see no new bytes.
		if s%5 == 1 {
			initiations++
		}
		health, conflict, unstable := e.observe(at(s), one(time.Time{}, uint64(initiations)*148, 0))
		want := TunnelHealthUnverified
		if s >= 21 {
			want = TunnelHealthNoConnection
		}
		if health != want || conflict || unstable {
			t.Fatalf("at %ds: got %v, %v, %v, want %v", s, health, conflict, unstable, want)
		}
	}
	if health, _, _ := e.observe(at(61), one(at(61), uint64(initiations)*148+148, 92)); health != TunnelHealthConnected {
		t.Fatalf("after handshake: got %v", health)
	}
}

func TestHealthOneSecondSamplesConflict(t *testing.T) {
	e := newHealthEvaluator()
	handshake := at(0)
	flaggedAt, unstableAt := -1, -1
	for s := 0; s <= 120; s++ {
		if s%20 == 0 {
			handshake = at(s)
		}
		_, conflict, unstable := e.observe(at(s), one(handshake, uint64(s)*100, uint64(s)*50))
		if unstable && unstableAt < 0 {
			unstableAt = s
		}
		if conflict && flaggedAt < 0 {
			flaggedAt = s
		}
	}
	if unstableAt != 20 || flaggedAt != 60 {
		t.Fatalf("unstable at %ds, flagged at %ds; want 20s and 60s as at five-second samples", unstableAt, flaggedAt)
	}
}

func TestHealthOneSecondSamplesNormalRekey(t *testing.T) {
	e := newHealthEvaluator()
	handshake := at(0)
	for s := 0; s <= 1800; s++ {
		if s%120 == 0 {
			handshake = at(s)
		}
		if health, conflict, unstable := e.observe(at(s), one(handshake, uint64(s)*100, uint64(s)*50)); conflict || unstable || health != TunnelHealthConnected {
			t.Fatalf("at %ds: got %v, %v, %v", s, health, conflict, unstable)
		}
	}
}

// A window opening and closing switches the rate in the middle of a stall; the verdict must not move.
func TestHealthMixedSampleRates(t *testing.T) {
	e := newHealthEvaluator()
	s, tx := 0, uint64(0)
	for s < 60 {
		step := 5
		if s >= 10 && s < 30 {
			step = 1
		}
		if s%5 == 0 {
			tx += 148
		}
		health, _, _ := e.observe(at(s), one(time.Time{}, tx, 0))
		want := TunnelHealthUnverified
		if s >= 20 {
			want = TunnelHealthNoConnection
		}
		if health != want {
			t.Fatalf("at %ds: got %v, want %v", s, health, want)
		}
		s += step
	}
}

func TestHealthCountsNewHandshakes(t *testing.T) {
	e := newHealthEvaluator()
	// A handshake the peer already had when first seen happened at some unknown time, so it is not counted.
	e.observe(at(0), one(at(-30), 100, 100))
	if e.newHandshakes != 0 {
		t.Fatalf("first sample: %d", e.newHandshakes)
	}
	e.observe(at(5), one(at(-30), 200, 200))
	if e.newHandshakes != 0 {
		t.Fatalf("same handshake: %d", e.newHandshakes)
	}
	e.observe(at(10), one(at(8), 300, 300))
	if e.newHandshakes != 1 {
		t.Fatalf("renewed: %d", e.newHandshakes)
	}
	e.observe(at(15), one(at(8), 400, 400))
	if e.newHandshakes != 0 {
		t.Fatalf("after renewal: %d", e.newHandshakes)
	}
}
