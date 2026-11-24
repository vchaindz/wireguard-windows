/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import "time"

// TunnelMetrics is what the manager has observed about a tunnel since the manager started. It is
// kept in memory only, so it starts afresh when the manager service does.
type TunnelMetrics struct {
	// ActiveSince is when the tunnel was activated, and zero while it is not active.
	ActiveSince time.Time
	// ConnectedSince is when the current connection was established, and zero while there is none.
	ConnectedSince time.Time
	// LastActiveEnd and LastActiveDuration describe the most recent time the tunnel was active
	// and has since been deactivated: when that ended and how long it lasted.
	LastActiveEnd      time.Time
	LastActiveDuration time.Duration
	// ConnectionFailures counts how often an active tunnel was found without a connection: its
	// peer never answered, or stopped answering.
	ConnectionFailures uint32
	// Reconnects counts how often a connection came back after it had been lost.
	Reconnects uint32
	// The counters of the network interface of the tunnel, for the time it has been active.
	InErrors, OutErrors, InDiscards, OutDiscards uint64
}

// interfaceCounters are the error counters of a network interface.
type interfaceCounters struct {
	inErrors, outErrors, inDiscards, outDiscards uint64
}

// A metricsRecorder turns what happens to one tunnel into its TunnelMetrics.
type metricsRecorder struct {
	metrics       TunnelMetrics
	everConnected bool
	failing       bool
}

func (r *metricsRecorder) started(now time.Time) {
	if !r.metrics.ActiveSince.IsZero() {
		return
	}
	r.metrics.ActiveSince = now
	r.metrics.ConnectedSince = time.Time{}
	r.metrics.InErrors, r.metrics.OutErrors, r.metrics.InDiscards, r.metrics.OutDiscards = 0, 0, 0, 0
	r.everConnected, r.failing = false, false
}

func (r *metricsRecorder) stopped(now time.Time) {
	if r.metrics.ActiveSince.IsZero() {
		return
	}
	r.metrics.LastActiveEnd = now
	r.metrics.LastActiveDuration = now.Sub(r.metrics.ActiveSince)
	r.metrics.ActiveSince, r.metrics.ConnectedSince = time.Time{}, time.Time{}
	r.failing = false
}

// observed records one sample of the connection check. A tunnel that is merely idle, so that its
// connection cannot be verified, counts neither as connected nor as failing.
func (r *metricsRecorder) observed(now time.Time, health TunnelHealth, counters *interfaceCounters) {
	if r.metrics.ActiveSince.IsZero() {
		return
	}
	switch {
	case health == TunnelHealthConnected:
		if r.metrics.ConnectedSince.IsZero() {
			r.metrics.ConnectedSince = now
			if r.everConnected {
				r.metrics.Reconnects++
			}
			r.everConnected = true
		}
		r.failing = false
	case health.IsNoConnection():
		if !r.failing {
			r.metrics.ConnectionFailures++
			r.failing = true
		}
		r.metrics.ConnectedSince = time.Time{}
	}
	if counters != nil {
		r.metrics.InErrors, r.metrics.OutErrors = counters.inErrors, counters.outErrors
		r.metrics.InDiscards, r.metrics.OutDiscards = counters.inDiscards, counters.outDiscards
	}
}

// trackedTunnelsMetrics is protected by trackedTunnelsLock. Entries stay when a tunnel is
// deactivated, so that it can be told when it was last active.
var trackedTunnelsMetrics = make(map[string]*metricsRecorder)

// withTunnelMetrics runs f on the recorder of a tunnel, creating it if need be.
func withTunnelMetrics(tunnelName string, f func(r *metricsRecorder)) {
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	recorder := trackedTunnelsMetrics[tunnelName]
	if recorder == nil {
		recorder = new(metricsRecorder)
		trackedTunnelsMetrics[tunnelName] = recorder
	}
	f(recorder)
}

func trackedTunnelMetrics(tunnelName string) (metrics TunnelMetrics) {
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	if recorder := trackedTunnelsMetrics[tunnelName]; recorder != nil {
		metrics = recorder.metrics
	}
	return
}
