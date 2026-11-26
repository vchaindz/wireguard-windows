/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"testing"
	"time"
)

func TestSamplesRingKeepsNewestInOrder(t *testing.T) {
	r := newSampleRing(5)
	for s := 1; s <= 12; s++ {
		r.push(TunnelSample{Time: at(s), RxBytes: uint64(s)})
	}
	all := r.since(time.Time{})
	if len(all) != 5 {
		t.Fatalf("got %d samples, want 5", len(all))
	}
	for i, sample := range all {
		if want := uint64(8 + i); sample.RxBytes != want {
			t.Fatalf("sample %d: got %d, want %d", i, sample.RxBytes, want)
		}
	}
	newer := r.since(at(10))
	if len(newer) != 2 || newer[0].RxBytes != 11 || newer[1].RxBytes != 12 {
		t.Fatalf("since 10s: got %+v", newer)
	}
	if got := r.since(at(12)); len(got) != 0 {
		t.Fatalf("since the newest: got %d samples", len(got))
	}
	// The result is a copy, so that a caller cannot disturb the ring.
	all[0].RxBytes = 0
	if r.since(time.Time{})[0].RxBytes != 8 {
		t.Fatal("ring changed through a returned slice")
	}
}

func TestSamplesRingBeforeFull(t *testing.T) {
	r := newSampleRing(5)
	r.push(TunnelSample{Time: at(1)})
	r.push(TunnelSample{Time: at(2)})
	if got := r.since(time.Time{}); len(got) != 2 || !got[0].Time.Equal(at(1)) {
		t.Fatalf("got %+v", got)
	}
}

func TestSamplesHealthSeverityOrder(t *testing.T) {
	order := []TunnelHealth{TunnelHealthUnknown, TunnelHealthUnverified, TunnelHealthConnected, TunnelHealthWaitingForPeer, TunnelHealthNoConnection, TunnelHealthNoConnectionNetworkBlocked}
	for i := 1; i < len(order); i++ {
		if healthSeverity(order[i]) <= healthSeverity(order[i-1]) {
			t.Fatalf("%v should be worse than %v", order[i], order[i-1])
		}
	}
}

// minuteStart is a time on a minute boundary, so that tests can count seconds into a minute.
var minuteStart = healthTestStart.Truncate(time.Minute).Add(10 * time.Minute)

func sec(seconds int) time.Time {
	return minuteStart.Add(time.Duration(seconds) * time.Second)
}

func TestSamplesFoldMinute(t *testing.T) {
	var f minuteFolder
	samples := []TunnelSample{
		{Time: sec(0), RxBytes: 100, TxBytes: 10, Health: TunnelHealthConnected, Probed: true, ProbesSent: 1, LatencyMicros: 10000, MaxLatencyMicros: 10000},
		{Time: sec(1), RxBytes: 200, TxBytes: 20, Health: TunnelHealthNoConnection, Probed: true, ProbesSent: 2, ProbesLost: 1, LatencyMicros: 40000, MaxLatencyMicros: 40000},
		{Time: sec(2), RxBytes: 300, TxBytes: 30, Health: TunnelHealthUnverified},
		{Time: sec(59), RxBytes: 400, TxBytes: 40, Health: TunnelHealthConnected, Probed: true, ProbesSent: 3, LatencyMicros: 20000, MaxLatencyMicros: 30000},
	}
	for _, sample := range samples {
		if _, ok := f.add(sample); ok {
			t.Fatalf("folded within the minute at %v", sample.Time)
		}
	}
	folded, ok := f.add(TunnelSample{Time: sec(60), RxBytes: 500, Health: TunnelHealthConnected})
	if !ok {
		t.Fatal("a sample of the next minute did not fold the previous one")
	}
	// Answered probes: 1 at 10 ms, 1 at 40 ms, 3 at 20 ms, so the mean is (10+40+60)/5 = 22 ms.
	want := TunnelSample{Time: sec(0), RxBytes: 400, TxBytes: 40, Health: TunnelHealthNoConnection, Probed: true, ProbesSent: 6, ProbesLost: 1, LatencyMicros: 22000, MaxLatencyMicros: 40000}
	if folded != want {
		t.Fatalf("got  %+v\nwant %+v", folded, want)
	}
	// The next minute starts from the sample that ended the previous one.
	next, ok := f.add(TunnelSample{Time: sec(125), RxBytes: 600, Health: TunnelHealthUnverified})
	if !ok || !next.Time.Equal(sec(60)) || next.RxBytes != 500 || next.Health != TunnelHealthConnected || next.Probed {
		t.Fatalf("second minute: got %+v", next)
	}
}

func TestSamplesFoldAllLost(t *testing.T) {
	var f minuteFolder
	f.add(TunnelSample{Time: sec(0), Health: TunnelHealthConnected, Probed: true, ProbesSent: 1, ProbesLost: 1})
	f.add(TunnelSample{Time: sec(5), Health: TunnelHealthConnected, Probed: true, ProbesSent: 1, ProbesLost: 1})
	folded, _ := f.add(TunnelSample{Time: sec(60)})
	if !folded.Probed || folded.ProbesSent != 2 || folded.ProbesLost != 2 || folded.LatencyMicros != 0 {
		t.Fatalf("got %+v", folded)
	}
}

func TestSamplesHistoryAtBothRates(t *testing.T) {
	for _, step := range []int{1, 5} {
		h := newSampleHistory()
		end := 3 * 3600
		for s := 0; s < end; s += step {
			h.add(TunnelSample{Time: sec(s), RxBytes: uint64(s), Health: TunnelHealthConnected})
		}
		fine, _ := h.since(SampleResolutionSecond, time.Time{})
		wantFine := min(end/step, fineSampleCapacity)
		if len(fine) != wantFine || fine[len(fine)-1].RxBytes != uint64(end-step) {
			t.Fatalf("step %d: %d fine samples, want %d", step, len(fine), wantFine)
		}
		minutes, _ := h.since(SampleResolutionMinute, time.Time{})
		// Every minute but the running one is folded.
		if len(minutes) != end/60-1 {
			t.Fatalf("step %d: %d minute samples, want %d", step, len(minutes), end/60-1)
		}
		for i, m := range minutes {
			if !m.Time.Equal(sec(i*60)) || m.RxBytes != uint64(i*60+60-step) {
				t.Fatalf("step %d, minute %d: got %+v", step, i, m)
			}
		}
		recent, _ := h.since(SampleResolutionMinute, sec(end-10*60))
		// Minutes starting after the cut-off, which is itself a minute start; the running minute is not there.
		if len(recent) != 8 {
			t.Fatalf("step %d: %d recent minutes, want 8", step, len(recent))
		}
		if _, err := h.since(SampleResolution(7), time.Time{}); err == nil {
			t.Fatal("unknown resolution accepted")
		}
	}
}

func TestSamplesMinuteRingCapacity(t *testing.T) {
	h := newSampleHistory()
	for m := 0; m <= minuteSampleCapacity+10; m++ {
		h.add(TunnelSample{Time: sec(m * 60)})
	}
	minutes, _ := h.since(SampleResolutionMinute, time.Time{})
	if len(minutes) != minuteSampleCapacity || !minutes[0].Time.Equal(sec(10*60)) {
		t.Fatalf("got %d minutes starting at %v", len(minutes), minutes[0].Time)
	}
}

func TestSamplesWatcherCount(t *testing.T) {
	if interval, _ := sampleInterval(); interval != healthSampleIntervalIdle {
		t.Fatalf("idle interval %v", interval)
	}
	_, changed := sampleInterval()
	addSampleWatcher(1)
	select {
	case <-changed:
	default:
		t.Fatal("first watcher did not wake the monitors")
	}
	_, changed = sampleInterval()
	addSampleWatcher(1)
	select {
	case <-changed:
		t.Fatal("second watcher woke the monitors needlessly")
	default:
	}
	if interval, _ := sampleInterval(); interval != healthSampleIntervalWatched {
		t.Fatalf("watched interval %v", interval)
	}
	addSampleWatcher(-1)
	addSampleWatcher(-1)
	select {
	case <-changed:
	default:
		t.Fatal("last watcher leaving did not wake the monitors")
	}
	if interval, _ := sampleInterval(); interval != healthSampleIntervalIdle {
		t.Fatalf("interval after watchers left %v", interval)
	}
}

func TestSamplesConnectionWatchIsUndone(t *testing.T) {
	s := &ManagerService{}
	s.Watch(true)
	s.Watch(true)
	if interval, _ := sampleInterval(); interval != healthSampleIntervalWatched {
		t.Fatalf("interval %v while watching", interval)
	}
	// What ServeConn does when the connection ends.
	s.Watch(false)
	if interval, _ := sampleInterval(); interval != healthSampleIntervalIdle {
		t.Fatalf("interval %v after the connection ended", interval)
	}
}

func TestSamplesFoldHandshakesAndWarnings(t *testing.T) {
	var f minuteFolder
	f.add(TunnelSample{Time: sec(0), Handshakes: 200})
	f.add(TunnelSample{Time: sec(10), Handshakes: 100, Unstable: true})
	f.add(TunnelSample{Time: sec(20), ConflictSuspected: true})
	folded, ok := f.add(TunnelSample{Time: sec(60)})
	if !ok || folded.Handshakes != 255 || !folded.Unstable || !folded.ConflictSuspected {
		t.Fatalf("got %+v", folded)
	}
}
