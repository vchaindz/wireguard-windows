/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"testing"
	"time"
)

func TestMetricsSession(t *testing.T) {
	var r metricsRecorder

	// Nothing is recorded for a tunnel that is not active.
	r.observed(at(0), TunnelHealthConnected, nil)
	if r.metrics != (TunnelMetrics{}) {
		t.Fatalf("recorded while inactive: %+v", r.metrics)
	}

	r.started(at(10))
	r.started(at(11)) // A second start of an active tunnel changes nothing.
	if !r.metrics.ActiveSince.Equal(at(10)) {
		t.Fatalf("active since %v, want %v", r.metrics.ActiveSince, at(10))
	}

	// The peer does not answer at first: one failure, however long it lasts.
	r.observed(at(15), TunnelHealthUnverified, nil)
	r.observed(at(20), TunnelHealthWaitingForPeer, nil)
	r.observed(at(25), TunnelHealthWaitingForPeer, nil)
	if r.metrics.ConnectionFailures != 1 || !r.metrics.ConnectedSince.IsZero() {
		t.Fatalf("while waiting: %+v", r.metrics)
	}

	// The first connection is not a reconnect.
	r.observed(at(30), TunnelHealthConnected, &interfaceCounters{inErrors: 1, outDiscards: 4})
	r.observed(at(35), TunnelHealthConnected, &interfaceCounters{inErrors: 2, outDiscards: 4})
	if r.metrics.Reconnects != 0 || !r.metrics.ConnectedSince.Equal(at(30)) || r.metrics.InErrors != 2 || r.metrics.OutDiscards != 4 {
		t.Fatalf("after connecting: %+v", r.metrics)
	}

	// Going idle is neither a failure nor the end of the connection.
	r.observed(at(300), TunnelHealthUnverified, nil)
	if r.metrics.ConnectionFailures != 1 || !r.metrics.ConnectedSince.Equal(at(30)) {
		t.Fatalf("while idle: %+v", r.metrics)
	}

	// Losing the connection and getting it back.
	r.observed(at(400), TunnelHealthNoConnectionNetworkBlocked, nil)
	r.observed(at(405), TunnelHealthNoConnection, nil)
	if r.metrics.ConnectionFailures != 2 || !r.metrics.ConnectedSince.IsZero() {
		t.Fatalf("after losing the connection: %+v", r.metrics)
	}
	r.observed(at(420), TunnelHealthConnected, nil)
	if r.metrics.Reconnects != 1 || !r.metrics.ConnectedSince.Equal(at(420)) {
		t.Fatalf("after reconnecting: %+v", r.metrics)
	}

	r.stopped(at(610))
	r.stopped(at(700)) // A second stop changes nothing.
	if !r.metrics.ActiveSince.IsZero() || !r.metrics.ConnectedSince.IsZero() || !r.metrics.LastActiveEnd.Equal(at(610)) || r.metrics.LastActiveDuration != 600*time.Second {
		t.Fatalf("after stopping: %+v", r.metrics)
	}
	if r.metrics.ConnectionFailures != 2 || r.metrics.Reconnects != 1 {
		t.Fatalf("counts did not survive stopping: %+v", r.metrics)
	}

	// The next session starts with fresh interface counters and keeps the history.
	r.started(at(1000))
	r.observed(at(1005), TunnelHealthConnected, nil)
	if r.metrics.InErrors != 0 || r.metrics.OutDiscards != 0 || r.metrics.Reconnects != 1 || !r.metrics.LastActiveEnd.Equal(at(610)) {
		t.Fatalf("second session: %+v", r.metrics)
	}
}

func TestMetricsReplacedListenPort(t *testing.T) {
	var r metricsRecorder
	r.listenPort(51820, 40000)
	if r.metrics.ReplacedListenPort != 0 {
		t.Fatal("a port was noted for a tunnel that is not active")
	}
	r.started(time.Unix(1700000000, 0))
	for _, c := range []struct{ configured, actual, want uint16 }{
		{51820, 51820, 0},
		{0, 40000, 0},
		{51820, 0, 0},
		{51820, 40000, 51820},
		{51820, 51820, 0},
	} {
		r.listenPort(c.configured, c.actual)
		if got := r.metrics.ReplacedListenPort; got != c.want {
			t.Errorf("configured %d, actual %d: got %d, want %d", c.configured, c.actual, got, c.want)
		}
	}
}
