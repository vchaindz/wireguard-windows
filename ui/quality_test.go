/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"math"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/manager"
)

// A probeFunc says what the probes of the i-th sample found; nil means that nothing was probed.
type probeFunc func(i int) (sent, lost uint16, latencyMicros uint32)

// sampleSeries makes count samples spaced by step that end at end, with traffic that rises and falls, and with
// probes if probe is given.
func sampleSeries(end time.Time, count int, step time.Duration, probe probeFunc) []manager.TunnelSample {
	samples := make([]manager.TunnelSample, count)
	var rx, tx float64 = 5e8, 1e8
	for i := range samples {
		wave := float64((i*37)%23) / 23
		rx += (200000 + 900000*wave*wave) * step.Seconds()
		tx += (40000 + 250000*(1-wave)) * step.Seconds()
		sample := manager.TunnelSample{
			Time:    end.Add(-time.Duration(count-1-i) * step),
			RxBytes: uint64(rx),
			TxBytes: uint64(tx),
			Health:  manager.TunnelHealthConnected,
		}
		if probe != nil {
			sent, lost, latency := probe(i)
			sample.Probed, sample.ProbesSent, sample.ProbesLost, sample.LatencyMicros, sample.MaxLatencyMicros = true, sent, lost, latency, latency
		}
		samples[i] = sample
	}
	return samples
}

// goodProbes answer every probe in 20 to 30 ms, with a short bad patch.
func goodProbes(i int) (uint16, uint16, uint32) {
	if i%700 > 640 && i%700 < 660 {
		return 1, 1, 0
	}
	return 1, 0, uint32(20000 + (i*7919)%10000)
}

func TestDeriveRates(t *testing.T) {
	start := time.Unix(1700000000, 0)
	at := func(seconds float64) time.Time { return start.Add(time.Duration(seconds * float64(time.Second))) }
	sample := func(seconds float64, rx, tx uint64) manager.TunnelSample {
		return manager.TunnelSample{Time: at(seconds), RxBytes: rx, TxBytes: tx}
	}
	if points := deriveRates(nil); len(points) != 0 {
		t.Fatalf("rates without samples: %v", points)
	}
	points := deriveRates([]manager.TunnelSample{
		// The first sample only sets the baseline.
		sample(0, 1000, 500),
		sample(2, 5000, 1500),
		// A sample right after is skipped, and its bytes count towards the next one.
		sample(2.1, 5100, 1500),
		sample(3, 6000, 1500),
		// Totals that go backwards mean a restarted tunnel: the next rate starts from there.
		sample(4, 10, 10),
		sample(5, 110, 60),
	})
	want := []ratePoint{{at(2), 2000, 500}, {at(3), 1000, 0}, {at(5), 100, 50}}
	if len(points) != len(want) {
		t.Fatalf("got %v, want %v", points, want)
	}
	for i := range want {
		if !points[i].at.Equal(want[i].at) || points[i].rx != want[i].rx || points[i].tx != want[i].tx {
			t.Errorf("rate %d: got %+v, want %+v", i, points[i], want[i])
		}
	}
	if rate := currentRate([]manager.TunnelSample{sample(0, 0, 0), sample(1, 300, 100)}); rate.rx != 300 || rate.tx != 100 {
		t.Errorf("current rate %+v", rate)
	}
}

func TestEndStampedAndRangeSamples(t *testing.T) {
	start := time.Unix(1700000000, 0).Truncate(time.Minute)
	minutes := []manager.TunnelSample{{Time: start, RxBytes: 100}, {Time: start.Add(time.Minute), RxBytes: 6100}}
	seconds := []manager.TunnelSample{
		{Time: start.Add(time.Minute + 30*time.Second), RxBytes: 5000},
		{Time: start.Add(2*time.Minute + 10*time.Second), RxBytes: 6200},
		{Time: start.Add(2*time.Minute + 11*time.Second), RxBytes: 6300},
	}
	merged := rangeSamples(tunnelSamples{seconds: seconds, minutes: minutes}, rangeDay)
	// The minutes move to their ends, and only the seconds after the last of them follow.
	if len(merged) != 4 || !merged[1].Time.Equal(start.Add(2*time.Minute)) || merged[2].RxBytes != 6200 {
		t.Fatalf("merged %+v", merged)
	}
	if minutes[1].Time != start.Add(time.Minute) {
		t.Fatal("endStamped changed its input")
	}
	rates := deriveRates(merged)
	if len(rates) == 0 || rates[0].rx != 100 {
		t.Fatalf("rate of the second minute: %+v", rates)
	}
	if got := rangeSamples(tunnelSamples{seconds: seconds}, rangeDay); len(got) != 3 {
		t.Errorf("without minutes, the day uses the seconds; got %d", len(got))
	}
	if got := rangeSamples(tunnelSamples{seconds: seconds, minutes: minutes}, rangeHour); len(got) != 3 {
		t.Errorf("the hour uses the seconds; got %d", len(got))
	}
}

func TestBucketPoints(t *testing.T) {
	start := time.Unix(1700000000, 0)
	point := func(seconds float64, value, weight float64, sent, lost int) chartPoint {
		return chartPoint{at: start.Add(time.Duration(seconds * float64(time.Second))), value: [2]float64{value, 2 * value}, weight: [2]float64{weight, weight}, sent: sent, lost: lost}
	}
	buckets := bucketPoints([]chartPoint{
		point(-1, 1000, 1, 1, 1), // before the range
		point(0, 10, 1, 1, 0),
		point(5, 40, 3, 3, 1), // same bucket, three times the weight
		point(25, 7, 1, 1, 0),
		point(60, 9, 1, 1, 0),    // the end of the range belongs to the last bucket
		point(61, 1000, 1, 1, 1), // after the range
		point(35, 5, 0, 2, 2),    // no weight: only its probes count
	}, start, time.Minute, 6)
	if len(buckets) != 6 {
		t.Fatalf("%d buckets", len(buckets))
	}
	if b := buckets[0]; !b.has[0] || b.value[0] != 32.5 || b.value[1] != 65 || b.sent != 4 || b.lost != 1 {
		t.Errorf("first bucket %+v", b)
	}
	if b := buckets[1]; b.has[0] || b.sent != 0 {
		t.Errorf("empty bucket %+v", b)
	}
	if b := buckets[2]; !b.has[0] || b.value[0] != 7 {
		t.Errorf("third bucket %+v", b)
	}
	if b := buckets[3]; b.has[0] || b.sent != 2 || b.lost != 2 {
		t.Errorf("bucket with only lost probes %+v", b)
	}
	if b := buckets[5]; !b.has[0] || b.value[0] != 9 {
		t.Errorf("last bucket %+v", b)
	}

	// However long the range, a chart has a bounded number of points.
	end := time.Now()
	samples := tunnelSamples{seconds: sampleSeries(end, secondSampleCapacity, time.Second, goodProbes), minutes: sampleSeries(end.Truncate(time.Minute).Add(-time.Minute), minuteSampleCapacity, time.Minute, goodProbes)}
	for r := chartRange(0); r < chartRangeCount; r++ {
		traffic := trafficBuckets(samples, r, end)
		latency := latencyBuckets(samples, r, end)
		if len(traffic) > 120 || len(latency) > 120 || len(traffic) != r.buckets() {
			t.Errorf("range %v: %d traffic and %d latency points", r, len(traffic), len(latency))
		}
		filled := 0
		for i := range traffic {
			if traffic[i].has[0] {
				filled++
			}
		}
		if filled < len(traffic)-2 {
			t.Errorf("range %v: only %d of %d points have traffic", r, filled, len(traffic))
		}
	}
	if latencyBuckets(tunnelSamples{seconds: sampleSeries(end, 60, time.Second, nil)}, rangeMinute, end) != nil {
		t.Error("latency points without probes")
	}
}

func TestSummarizeQuality(t *testing.T) {
	end := time.Unix(1700000000, 0)
	if summary := summarizeQuality(nil); summary.hasData {
		t.Error("data without samples")
	}
	if summary := summarizeQuality(sampleSeries(end, 60, time.Second, nil)); summary.hasData || summary.noReply() || summary.poor() {
		t.Errorf("unprobed samples: %+v", summary)
	}

	// Latencies 10, 20, 30 ms over three samples, the middle one with two answered probes: the mean is
	// weighted, the jitter is the mean step between answers.
	latencies := []uint32{10000, 20000, 30000}
	samples := sampleSeries(end, 3, time.Second, func(i int) (uint16, uint16, uint32) {
		if i == 1 {
			return 3, 1, latencies[i]
		}
		return 1, 0, latencies[i]
	})
	summary := summarizeQuality(samples)
	if !summary.hasData || !summary.answered || summary.sent != 5 || summary.lost != 1 {
		t.Fatalf("summary %+v", summary)
	}
	if summary.latency != 20*time.Millisecond || summary.jitter != 10*time.Millisecond {
		t.Errorf("latency %v, jitter %v", summary.latency, summary.jitter)
	}
	if math.Abs(summary.lossPercent()-20) > 1e-9 {
		t.Errorf("loss %v", summary.lossPercent())
	}

	// Only the last minute counts: an hour of loss before it does not.
	samples = sampleSeries(end, 3600, time.Second, func(i int) (uint16, uint16, uint32) {
		if i < 3600-60 {
			return 1, 1, 0
		}
		return 1, 0, 25000
	})
	if summary := summarizeQuality(samples); summary.sent != 60 || summary.lost != 0 || summary.poor() {
		t.Errorf("last minute: %+v", summary)
	}

	// Loss at the threshold, with enough probes, is poor; with too few probes it is not called yet.
	lossy := func(count, every int) []manager.TunnelSample {
		return sampleSeries(end, count, time.Second, func(i int) (uint16, uint16, uint32) {
			if i%every == 0 {
				return 1, 1, 0
			}
			return 1, 0, 30000
		})
	}
	if summary := summarizeQuality(lossy(60, 20)); !summary.poor() || summary.lossPercent() != 5 {
		t.Errorf("5 %% loss: %+v, %v", summary, summary.lossPercent())
	}
	if summary := summarizeQuality(lossy(60, 30)); summary.poor() {
		t.Errorf("3 %% loss is poor: %+v", summary)
	}
	if summary := summarizeQuality(lossy(poorQualityMinProbes-1, 2)); summary.poor() {
		t.Errorf("poor after only %d probes", summary.sent)
	}

	// Slow answers are poor too.
	slow := sampleSeries(end, 30, time.Second, func(int) (uint16, uint16, uint32) { return 1, 0, uint32(poorQualityLatency / time.Microsecond) })
	if summary := summarizeQuality(slow); !summary.poor() || summary.lossPercent() != 0 {
		t.Errorf("slow: %+v", summary)
	}

	// A target that never answered is told apart from loss.
	silent := sampleSeries(end, 30, time.Second, func(int) (uint16, uint16, uint32) { return 1, 1, 0 })
	summary = summarizeQuality(silent)
	if !summary.noReply() || summary.poor() || summary.everAnswered {
		t.Errorf("silent target: %+v", summary)
	}
	if text := qualityText(summary); strings.Contains(text, "100") {
		t.Errorf("silent target reported as %q", text)
	}
	connected := &tunnelEntry{state: manager.TunnelStarted, health: manager.TunnelHealthConnected}
	if title, text := qualityWarning(connected, summary); len(title) == 0 || strings.Contains(text, "100") {
		t.Errorf("silent target warning %q: %q", title, text)
	}
	// Once something answered, losing everything is loss.
	silent[0].ProbesLost, silent[0].LatencyMicros = 0, 20000
	if summary := summarizeQuality(silent); summary.noReply() || !summary.poor() {
		t.Errorf("loss after answers: %+v", summary)
	}
	// Without a connection, the state of the tunnel says more than the probes.
	if title, _ := qualityWarning(&tunnelEntry{state: manager.TunnelStarted, health: manager.TunnelHealthNoConnection}, summarizeQuality(lossy(60, 2))); len(title) > 0 {
		t.Errorf("quality warning without connection: %q", title)
	}
}

func TestAppendSamples(t *testing.T) {
	end := time.Unix(1700000000, 0)
	held := appendSamples(nil, sampleSeries(end, 10, time.Second, nil), 25)
	held = appendSamples(held, sampleSeries(end.Add(30*time.Second), 20, time.Second, nil), 25)
	if len(held) != 25 || !held[24].Time.Equal(end.Add(30*time.Second)) {
		t.Errorf("%d held, newest %v", len(held), held[len(held)-1].Time)
	}
}

func TestChartSlotAndPolyline(t *testing.T) {
	for _, c := range []struct {
		x    float64
		want int
	}{{9, -1}, {10, 0}, {14.9, 0}, {15, 1}, {109.9, 19}, {110, -1}} {
		if got := chartSlot(c.x, 10, 100, 20); got != c.want {
			t.Errorf("x %v: slot %d, want %d", c.x, got, c.want)
		}
	}
	s := &scene{}
	var points [][2]float64
	for i := 0; i < 40; i++ {
		points = append(points, [2]float64{float64(i), float64(i % 3)})
	}
	s.polyline(1, theme.text, points)
	drawn := 0
	for i, shape := range s.shapes {
		if shape.nPoints > len(shape.points) || shape.nPoints < 2 {
			t.Fatalf("shape %d has %d points", i, shape.nPoints)
		}
		if i > 0 && shape.points[0] != s.shapes[i-1].points[s.shapes[i-1].nPoints-1] {
			t.Errorf("shape %d does not continue the one before", i)
		}
		drawn += shape.nPoints - 1
	}
	if drawn != len(points)-1 {
		t.Errorf("%d segments drawn, want %d", drawn, len(points)-1)
	}
}

// TestRenderQuality draws the screens with measured connection quality: the status screen over an hour, the
// details screen with its quality rows and switch, poor quality, a target that does not answer, the day, the
// switch disabled by policy, and a graph under the mouse.
func TestRenderQuality(t *testing.T) {
	wasAdmin := IsAdmin
	IsAdmin = true
	defer func() { IsAdmin = wasAdmin }()

	now := time.Now()
	office := tunnelEntry{tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStarted, health: manager.TunnelHealthConnected}
	office.config = sampleConfig("office", "10.8.0.2/24", 42*time.Second, 1331439862, 228589568)
	office.metrics = manager.TunnelMetrics{ActiveSince: now.Add(-3 * time.Hour), ConnectedSince: now.Add(-47 * time.Minute)}
	office.settings, office.probingAllowed, office.settingsLoaded = manager.TunnelSettings{Probe: true}, true, true
	backup := tunnelEntry{tunnel: manager.Tunnel{Name: "backup-site"}, state: manager.TunnelStopped}

	good := tunnelSamples{
		// The window was hidden for part of the hour, when the manager sampled every five seconds.
		seconds: append(sampleSeries(now.Add(-20*time.Minute), 480, 5*time.Second, goodProbes), sampleSeries(now, 1199, time.Second, goodProbes)...),
		minutes: sampleSeries(now.Truncate(time.Minute).Add(-time.Minute), 600, time.Minute, goodProbes),
	}
	poor := tunnelSamples{seconds: sampleSeries(now, 600, time.Second, func(i int) (uint16, uint16, uint32) {
		if i%8 == 0 {
			return 1, 1, 0
		}
		return 1, 0, uint32(80000 + (i*7919)%60000)
	})}
	silent := tunnelSamples{seconds: sampleSeries(now, 90, time.Second, func(int) (uint16, uint16, uint32) { return 1, 1, 0 })}
	unprobed := tunnelSamples{seconds: sampleSeries(now, 600, time.Second, nil)}

	window := func(samples tunnelSamples, r chartRange, details string, edit func(entry *tunnelEntry)) *ManageTunnelsWindow {
		entry := office
		if edit != nil {
			edit(&entry)
		}
		mtw := &ManageTunnelsWindow{timeRange: r, model: &appModel{entries: []tunnelEntry{backup, entry}, globalState: manager.TunnelStarted, samples: map[string]tunnelSamples{"office": samples}}}
		if len(details) > 0 {
			mtw.screen, mtw.detailsName = screenDetails, details
		}
		return mtw
	}
	build := func(mtw *ManageTunnelsWindow) func(s *scene, width, height float64) {
		if mtw.screen == screenDetails {
			return mtw.buildDetails
		}
		return mtw.buildStatus
	}

	for _, c := range []struct {
		name   string
		mtw    *ManageTunnelsWindow
		scroll float64
		want   []string
		hits   []string
	}{
		{"quality-status-hour", window(good, rangeHour, "", nil), 0, []string{"Quality", " ms · ", "Latency"}, []string{"range:0", "range:1", "range:2", "chart:traffic", "chart:latency"}},
		{"quality-status-unprobed", window(unprobed, rangeMinute, "", nil), 0, nil, []string{"chart:traffic"}},
		{"quality-status-poor", window(poor, rangeMinute, "", nil), 0, []string{"Poor connection quality"}, nil},
		{"quality-status-noreply", window(silent, rangeMinute, "", nil), 0, []string{"Quality cannot be measured", "No reply"}, nil},
		{"quality-details", window(good, rangeMinute, "office", nil), 0, []string{"Latency", "Jitter", "Loss"}, []string{"chart:latency"}},
		{"quality-details-settings", window(good, rangeMinute, "office", nil), 520, []string{"Measure connection quality", "automatic", "Change…"}, []string{"probe", "probe-target"}},
		{"quality-details-policy", window(unprobed, rangeDay, "office", func(entry *tunnelEntry) {
			entry.probingAllowed = false
			entry.settings = manager.TunnelSettings{Probe: true, ProbeTarget: "10.8.0.1"}
		}), 380, []string{"Disabled by policy", "10.8.0.1"}, nil},
		{"quality-details-day", window(good, rangeDay, "office", nil), 0, []string{"24 h ago"}, nil},
	} {
		s, img := renderSceneWith(t, 524, 820, 1, c.scroll, "", build(c.mtw))
		for _, want := range c.want {
			found := false
			for _, text := range s.texts {
				if strings.Contains(text.text, want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: no text with %q", c.name, want)
			}
		}
		for _, id := range c.hits {
			if s.hitByID(id) == nil {
				t.Errorf("%s: no region %q", c.name, id)
			}
		}
		seen := make(map[string]bool)
		for _, hit := range s.hits {
			if hit.action != nil && seen[hit.id] && !strings.HasPrefix(hit.id, "copy:") {
				t.Errorf("%s: region %q twice", c.name, hit.id)
			}
			seen[hit.id] = true
		}
		writePNG(t, c.name, img)
	}

	// The policy switch cannot be operated, and the address cannot be changed.
	s, _ := renderSceneWith(t, 524, 820, 1, 380, "", build(window(unprobed, rangeMinute, "office", func(entry *tunnelEntry) { entry.probingAllowed = false })))
	if s.hitByID("probe") != nil || s.hitByID("probe-target") != nil {
		t.Error("measuring can be switched although policy forbids it")
	}
	// The status screen leaves the quality out without probes.
	s, _ = renderSceneWith(t, 524, 820, 1, 0, "", build(window(unprobed, rangeMinute, "", nil)))
	for _, text := range s.texts {
		if text.text == "Quality" {
			t.Error("quality tile without probes")
		}
	}

	// A graph under the mouse says what it shows there.
	mtw := window(good, rangeHour, "", nil)
	s, _ = renderSceneWith(t, 524, 820, 1, 0, "", mtw.buildStatus)
	for _, id := range []string{"chart:traffic", "chart:latency"} {
		hit := s.hitByID(id)
		if hit == nil || !hit.tracksMouse || hit.action != nil {
			t.Fatalf("%s: no region that follows the mouse", id)
		}
		mouse := [2]float64{hit.rect.x + hit.rect.w*0.8, hit.rect.y + hit.rect.h/2}
		hovered, img := renderSceneMouse(t, 524, 820, 1, 0, "", &mouse, mtw.buildStatus)
		found := false
		for _, text := range hovered.texts {
			// The caption becomes the time under the mouse.
			if len(text.text) == len("15:04:05") && strings.Count(text.text, ":") == 2 {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no time shown under the mouse", id)
		}
		if len(hovered.shapes) <= len(s.shapes) {
			t.Errorf("%s: no marker drawn under the mouse", id)
		}
		writePNG(t, "quality-hover-"+strings.TrimPrefix(id, "chart:"), img)
	}
	for _, id := range s.focusOrder() {
		if strings.HasPrefix(id, "chart:") {
			t.Errorf("graph %q takes the keyboard focus", id)
		}
	}
}
