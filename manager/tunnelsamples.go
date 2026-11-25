/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"errors"
	"time"
)

// TunnelSample is one observation of a started tunnel. The manager keeps recent samples in memory so that a
// window that opens can draw the past at once instead of building its graphs up from nothing.
type TunnelSample struct {
	Time             time.Time
	RxBytes, TxBytes uint64 // totals over all peers at that time
	Health           TunnelHealth
	Probed           bool // false: no latency measurement in this sample
	ProbesSent       uint16
	ProbesLost       uint16
	LatencyMicros    uint32 // mean round trip of the answered probes, 0 if none answered
	MaxLatencyMicros uint32
	// Handshakes counts the handshakes that completed since the previous sample, so that renewals coming
	// unusually close together show as a pattern over time.
	Handshakes uint8
	// ConflictSuspected and Unstable are the warnings of the connection check at the time of the sample.
	ConflictSuspected, Unstable bool
}

// SampleResolution selects between the samples as taken and their one-per-minute summary.
type SampleResolution int

const (
	SampleResolutionSecond SampleResolution = iota
	SampleResolutionMinute
)

const (
	// An hour at one sample per second, and five hours at one per five seconds.
	fineSampleCapacity = 3600
	// A day of minutes.
	minuteSampleCapacity = 1440
)

// healthSeverity ranks health for summarising: a minute in which the network was blocked even briefly is
// reported as such, so that short outages stay visible at low resolution.
func healthSeverity(health TunnelHealth) int {
	switch health {
	case TunnelHealthNoConnectionNetworkBlocked:
		return 5
	case TunnelHealthNoConnection:
		return 4
	case TunnelHealthWaitingForPeer:
		return 3
	case TunnelHealthConnected:
		return 2
	case TunnelHealthUnverified:
		return 1
	}
	return 0
}

// A sampleRing keeps the most recent samples up to its capacity, in the order they were added.
type sampleRing struct {
	samples  []TunnelSample
	capacity int
	next     int // Where the next sample goes once the ring is full; it is then also the oldest.
}

func newSampleRing(capacity int) *sampleRing {
	return &sampleRing{capacity: capacity}
}

func (r *sampleRing) push(sample TunnelSample) {
	if len(r.samples) < r.capacity {
		r.samples = append(r.samples, sample)
		return
	}
	r.samples[r.next] = sample
	r.next = (r.next + 1) % r.capacity
}

// since returns a copy of the samples newer than the given time, oldest first. A zero time returns all.
func (r *sampleRing) since(since time.Time) []TunnelSample {
	result := make([]TunnelSample, 0, len(r.samples))
	add := func(samples []TunnelSample) {
		for i := range samples {
			if since.IsZero() || samples[i].Time.After(since) {
				result = append(result, samples[i])
			}
		}
	}
	add(r.samples[r.next:])
	add(r.samples[:r.next])
	return result
}

// A minuteFolder collects the samples of one minute and summarises them once a sample of another minute
// arrives.
type minuteFolder struct {
	minute          time.Time
	count           int
	summary         TunnelSample
	answered        uint64 // Probes answered, the weights of the latency mean.
	latencyWeighted uint64 // Sum of each sample's mean latency times its answered probes.
}

// add takes the next sample and returns the summary of the previous minute when this sample starts a new one.
func (f *minuteFolder) add(sample TunnelSample) (folded TunnelSample, ok bool) {
	minute := sample.Time.Truncate(time.Minute)
	if f.count > 0 && !minute.Equal(f.minute) {
		folded, ok = f.result(), true
		*f = minuteFolder{}
	}
	if f.count == 0 {
		f.minute = minute
		f.summary = TunnelSample{Time: minute}
	}
	f.count++
	f.summary.RxBytes, f.summary.TxBytes = sample.RxBytes, sample.TxBytes
	if f.count == 1 || healthSeverity(sample.Health) > healthSeverity(f.summary.Health) {
		f.summary.Health = sample.Health
	}
	f.summary.Handshakes = saturatingAdd8(f.summary.Handshakes, sample.Handshakes)
	f.summary.ConflictSuspected = f.summary.ConflictSuspected || sample.ConflictSuspected
	f.summary.Unstable = f.summary.Unstable || sample.Unstable
	if sample.Probed {
		f.summary.Probed = true
		f.summary.ProbesSent = saturatingAdd16(f.summary.ProbesSent, sample.ProbesSent)
		f.summary.ProbesLost = saturatingAdd16(f.summary.ProbesLost, sample.ProbesLost)
		if sample.ProbesSent > sample.ProbesLost {
			answered := uint64(sample.ProbesSent - sample.ProbesLost)
			f.answered += answered
			f.latencyWeighted += uint64(sample.LatencyMicros) * answered
		}
		f.summary.MaxLatencyMicros = max(f.summary.MaxLatencyMicros, sample.MaxLatencyMicros)
	}
	return
}

// result is the summary of the minute so far: the byte totals at its end, its worst health, all of its
// handshakes and probes, whether any sample carried a warning, and the mean latency of the probes weighted by how
// many probes each sample had answered.
func (f *minuteFolder) result() TunnelSample {
	summary := f.summary
	if f.answered > 0 {
		summary.LatencyMicros = uint32(f.latencyWeighted / f.answered)
	}
	return summary
}

func saturatingAdd8(a, b uint8) uint8 {
	if sum := uint16(a) + uint16(b); sum <= 0xff {
		return uint8(sum)
	}
	return 0xff
}

func saturatingAdd16(a, b uint16) uint16 {
	if sum := uint32(a) + uint32(b); sum <= 0xffff {
		return uint16(sum)
	}
	return 0xffff
}

// sampleHistory is what is kept about one started tunnel: its samples as taken, and one per finished minute.
// The minute that is still running is not in the minute ring yet; its samples are in the fine ring.
type sampleHistory struct {
	fine, minutes *sampleRing
	folder        minuteFolder
}

func newSampleHistory() *sampleHistory {
	return &sampleHistory{fine: newSampleRing(fineSampleCapacity), minutes: newSampleRing(minuteSampleCapacity)}
}

func (h *sampleHistory) add(sample TunnelSample) {
	h.fine.push(sample)
	if folded, ok := h.folder.add(sample); ok {
		h.minutes.push(folded)
	}
}

func (h *sampleHistory) since(resolution SampleResolution, since time.Time) ([]TunnelSample, error) {
	switch resolution {
	case SampleResolutionSecond:
		return h.fine.since(since), nil
	case SampleResolutionMinute:
		return h.minutes.since(since), nil
	}
	return nil, errors.New("Unknown sample resolution")
}

// trackedTunnelsSamples is protected by trackedTunnelsLock. An entry exists while the tunnel's health monitor
// runs and is dropped when the tunnel stops, so that nothing about past sessions is kept.
var trackedTunnelsSamples = make(map[string]*sampleHistory)

func trackedTunnelSamples(tunnelName string, resolution SampleResolution, since time.Time) ([]TunnelSample, error) {
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	history := trackedTunnelsSamples[tunnelName]
	if history == nil {
		if resolution != SampleResolutionSecond && resolution != SampleResolutionMinute {
			return nil, errors.New("Unknown sample resolution")
		}
		return nil, nil
	}
	return history.since(resolution, since)
}
