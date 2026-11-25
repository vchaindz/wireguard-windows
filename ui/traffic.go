/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"math"
	"time"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

const (
	// secondSampleCapacity is how many of the manager's per-second samples the UI keeps per tunnel, as many as
	// the manager itself holds.
	secondSampleCapacity = 3600
	// minuteSampleCapacity is a day of per-minute samples.
	minuteSampleCapacity = 1440
	// minuteSampleRefresh is how often the per-minute samples are fetched; a new one appears once a minute.
	minuteSampleRefresh = 30 * time.Second
)

// tunnelSamples is what the manager has sampled of one started tunnel. The slices are never changed once handed
// to the UI thread: the worker only appends past their ends or replaces them.
type tunnelSamples struct {
	seconds []manager.TunnelSample
	// minutes is filled only while some screen shows a range that needs it.
	minutes []manager.TunnelSample
}

// appendSamples adds newer samples and drops the oldest beyond the capacity.
func appendSamples(samples, newer []manager.TunnelSample, capacity int) []manager.TunnelSample {
	samples = append(samples, newer...)
	if len(samples) > capacity {
		samples = samples[len(samples)-capacity:]
	}
	return samples
}

// A ratePoint is the traffic rate in bytes per second over the interval that ends at its time.
type ratePoint struct {
	at     time.Time
	rx, tx float64
}

// deriveRates turns samples of running byte totals into rates between consecutive samples. Totals that go
// backwards mean the tunnel was restarted, so the next rate is measured from there. A sample that follows the
// previous one too closely is skipped, as its rate would be noise; its bytes count towards the next one.
func deriveRates(samples []manager.TunnelSample) []ratePoint {
	if len(samples) == 0 {
		return nil
	}
	var points []ratePoint
	base := samples[0]
	for _, current := range samples[1:] {
		if current.RxBytes < base.RxBytes || current.TxBytes < base.TxBytes {
			base = current
			continue
		}
		elapsed := current.Time.Sub(base.Time)
		if elapsed < 500*time.Millisecond {
			continue
		}
		seconds := elapsed.Seconds()
		points = append(points, ratePoint{current.Time, float64(current.RxBytes-base.RxBytes) / seconds, float64(current.TxBytes-base.TxBytes) / seconds})
		base = current
	}
	return points
}

// endStamped moves per-minute samples, which are stamped at the start of their minute but carry the totals at
// its end, to the end of their minute, so that they read like the per-second samples.
func endStamped(samples []manager.TunnelSample) []manager.TunnelSample {
	moved := make([]manager.TunnelSample, len(samples))
	for i := range samples {
		moved[i] = samples[i]
		moved[i].Time = samples[i].Time.Add(time.Minute)
	}
	return moved
}

// currentRate is the most recent traffic rate, or zero if there is none.
func currentRate(samples []manager.TunnelSample) ratePoint {
	// Only the end matters, so only the end is looked at.
	if len(samples) > 8 {
		samples = samples[len(samples)-8:]
	}
	if points := deriveRates(samples); len(points) > 0 {
		return points[len(points)-1]
	}
	return ratePoint{}
}

// A chartPoint is one or two values at a time, each with a weight for averaging, and for latency the probes
// sent and lost.
type chartPoint struct {
	at         time.Time
	value      [2]float64
	weight     [2]float64
	sent, lost int
}

// A chartBucket summarises the points that fall into one slot of a chart.
type chartBucket struct {
	value      [2]float64 // weighted mean
	has        [2]bool
	sent, lost int
	// at is the time of the newest point in the bucket. It names the bucket across frames, whose slots move
	// with the clock.
	at time.Time
}

// bucketPoints sorts points into count slots of equal length starting at start and spanning span; points
// outside are dropped. Values are averaged by their weights, and probes are added up.
func bucketPoints(points []chartPoint, start time.Time, span time.Duration, count int) []chartBucket {
	buckets := make([]chartBucket, count)
	if count <= 0 || span <= 0 {
		return buckets
	}
	var sums, weights = make([][2]float64, count), make([][2]float64, count)
	for _, point := range points {
		offset := point.at.Sub(start)
		if offset < 0 || offset > span {
			continue
		}
		index := int(int64(offset) * int64(count) / int64(span))
		if index >= count {
			index = count - 1
		}
		for series := range point.value {
			if point.weight[series] > 0 {
				sums[index][series] += point.value[series] * point.weight[series]
				weights[index][series] += point.weight[series]
			}
		}
		buckets[index].sent += point.sent
		buckets[index].lost += point.lost
		if point.at.After(buckets[index].at) {
			buckets[index].at = point.at
		}
	}
	for i := range buckets {
		for series := range sums[i] {
			if weights[i][series] > 0 {
				buckets[i].value[series] = sums[i][series] / weights[i][series]
				buckets[i].has[series] = true
			}
		}
	}
	return buckets
}

// ratePoints makes chart points of traffic rates: received first, sent second.
func ratePoints(rates []ratePoint) []chartPoint {
	points := make([]chartPoint, len(rates))
	for i, rate := range rates {
		points[i] = chartPoint{at: rate.at, value: [2]float64{rate.rx, rate.tx}, weight: [2]float64{1, 1}}
	}
	return points
}

// latencyPoints makes chart points of the probes in samples: the mean latency in milliseconds, weighted by the
// probes that were answered, and the probes sent and lost. Samples without probes are left out.
func latencyPoints(samples []manager.TunnelSample) []chartPoint {
	var points []chartPoint
	for i := range samples {
		sample := &samples[i]
		if !sample.Probed {
			continue
		}
		point := chartPoint{at: sample.Time, sent: int(sample.ProbesSent), lost: int(sample.ProbesLost)}
		if answered := int(sample.ProbesSent) - int(sample.ProbesLost); answered > 0 && sample.LatencyMicros > 0 {
			point.value[0] = float64(sample.LatencyMicros) / 1000
			point.weight[0] = float64(answered)
		}
		points = append(points, point)
	}
	return points
}

// anyProbed reports whether some sample in the time range carries a probe result.
func anyProbed(samples []manager.TunnelSample, start, end time.Time) bool {
	for i := len(samples) - 1; i >= 0; i-- {
		if samples[i].Time.Before(start) {
			break
		}
		if samples[i].Probed && !samples[i].Time.After(end) {
			return true
		}
	}
	return false
}

// Connection quality

const (
	// qualityWindow is how far back the quality summary looks.
	qualityWindow = time.Minute
	// A connection is called poor only after enough probes, so that one lost ping right after starting does not
	// raise an alarm.
	poorQualityMinProbes = 20
	// poorQualityLossPercent is the share of lost probes from which the connection is called poor.
	poorQualityLossPercent = 5.0
	// poorQualityLatency is the mean round trip from which the connection is called poor. It is well above what
	// even distant servers take, so that it points at a real problem rather than at distance.
	poorQualityLatency = 400 * time.Millisecond
	// noReplyMinProbes is how many probes must have gone unanswered, without any answer ever, before the
	// target is said not to answer.
	noReplyMinProbes = 10
)

// A qualitySummary describes the probes of the last minute.
type qualitySummary struct {
	// hasData is set if any probe finished in the last minute.
	hasData    bool
	sent, lost int
	// answered is set if any probe in the last minute was answered; everAnswered if any probe of all samples was.
	answered, everAnswered bool
	latency, jitter        time.Duration
}

// summarizeQuality looks at the minute before the newest sample: how many probes were sent and lost, their
// mean round trip weighted by the probes each sample had answered, and the jitter, which is the mean absolute
// difference between consecutive answered round trips.
func summarizeQuality(samples []manager.TunnelSample) (summary qualitySummary) {
	if len(samples) == 0 {
		return
	}
	for i := range samples {
		if samples[i].Probed && samples[i].LatencyMicros > 0 {
			summary.everAnswered = true
			break
		}
	}
	since := samples[len(samples)-1].Time.Add(-qualityWindow)
	first := len(samples)
	for first > 0 && samples[first-1].Time.After(since) {
		first--
	}
	var latencySum, answeredSum, jitterSum float64
	var jitterCount int
	previous := -1.0
	for _, sample := range samples[first:] {
		if !sample.Probed {
			continue
		}
		summary.hasData = true
		summary.sent += int(sample.ProbesSent)
		summary.lost += int(sample.ProbesLost)
		answered := int(sample.ProbesSent) - int(sample.ProbesLost)
		if answered <= 0 || sample.LatencyMicros == 0 {
			continue
		}
		latency := float64(sample.LatencyMicros)
		latencySum += latency * float64(answered)
		answeredSum += float64(answered)
		if previous >= 0 {
			jitterSum += math.Abs(latency - previous)
			jitterCount++
		}
		previous = latency
	}
	if answeredSum > 0 {
		summary.answered = true
		summary.latency = time.Duration(latencySum/answeredSum) * time.Microsecond
	}
	if jitterCount > 0 {
		summary.jitter = time.Duration(jitterSum/float64(jitterCount)) * time.Microsecond
	}
	return
}

// lossPercent is the share of probes of the last minute that got no answer.
func (summary qualitySummary) lossPercent() float64 {
	if summary.sent == 0 {
		return 0
	}
	return float64(summary.lost) * 100 / float64(summary.sent)
}

// noReply reports whether the target has never answered although it was asked often enough to tell.
func (summary qualitySummary) noReply() bool {
	return summary.hasData && !summary.everAnswered && summary.sent >= noReplyMinProbes
}

// poor reports whether the last minute had too much loss or too slow answers.
func (summary qualitySummary) poor() bool {
	if !summary.everAnswered || summary.sent < poorQualityMinProbes {
		return false
	}
	return summary.lossPercent() >= poorQualityLossPercent || summary.answered && summary.latency >= poorQualityLatency
}

func formatLatency(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	if ms == 0 {
		return l18n.Sprintf("0 ms")
	}
	if ms < 10 {
		return l18n.Sprintf("%.1f ms", ms)
	}
	return l18n.Sprintf("%.0f ms", ms)
}

func formatPercent(percent float64) string {
	if percent > 0 && percent < 1 {
		return l18n.Sprintf("<1 %%")
	}
	return l18n.Sprintf("%.0f %%", percent)
}

// qualityText is the short form of the summary, as on the status screen.
func qualityText(summary qualitySummary) string {
	if summary.noReply() || summary.hasData && !summary.answered && !summary.everAnswered {
		return l18n.Sprintf("No reply")
	}
	if !summary.answered {
		return l18n.Sprintf("%s loss", formatPercent(summary.lossPercent()))
	}
	return l18n.Sprintf("%s · %s loss", formatLatency(summary.latency), formatPercent(summary.lossPercent()))
}

// qualityWarning is the notice about the quality of a connection, if there is something to say. It is only
// given for a connected tunnel, as otherwise the state of the tunnel already says more.
func qualityWarning(entry *tunnelEntry, summary qualitySummary) (title, text string) {
	if entry.state != manager.TunnelStarted || entry.health != manager.TunnelHealthConnected {
		return "", ""
	}
	switch {
	case summary.noReply():
		return l18n.Sprintf("Quality cannot be measured"), l18n.Sprintf("The address used to measure the connection does not answer pings, so latency and loss are unknown. This says nothing about the tunnel itself. Choose another address on the details screen.")
	case summary.poor() && summary.lossPercent() >= poorQualityLossPercent:
		return l18n.Sprintf("Poor connection quality"), l18n.Sprintf("%s of the test pings in the last minute got no answer. Pages may load slowly and calls may break up.", formatPercent(summary.lossPercent()))
	case summary.poor():
		return l18n.Sprintf("Slow connection"), l18n.Sprintf("Answers through the tunnel took %s on average in the last minute, which makes the connection feel slow.", formatLatency(summary.latency))
	}
	return "", ""
}

// formatDuration writes a length of time with the one or two units that matter.
func formatDuration(d time.Duration) string {
	seconds := int(d / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	switch {
	case seconds < 60:
		return l18n.Sprintf("%d s", seconds)
	case seconds < 60*60:
		return l18n.Sprintf("%d min", seconds/60)
	case seconds < 24*60*60:
		return l18n.Sprintf("%d h %d min", seconds/3600, seconds%3600/60)
	}
	return l18n.Sprintf("%d d %d h", seconds/86400, seconds%86400/3600)
}

// lastActiveText says when a tunnel that is not active was last active and for how long, or
// nothing if that is not known.
func lastActiveText(metrics *manager.TunnelMetrics, now time.Time) string {
	if metrics.LastActiveEnd.IsZero() {
		return ""
	}
	return l18n.Sprintf("last active %s for %s", formatAgo(now.Sub(metrics.LastActiveEnd)), formatDuration(metrics.LastActiveDuration))
}

// connectionRows are the metrics of a tunnel as shown on its details screen.
func connectionRows(entry *tunnelEntry, samples tunnelSamples, now time.Time) []detailRow {
	metrics := &entry.metrics
	var rows []detailRow
	if entry.state == manager.TunnelStarted && !metrics.ActiveSince.IsZero() {
		rows = append(rows, detailRow{label: l18n.Sprintf("Active for"), value: formatDuration(now.Sub(metrics.ActiveSince))})
		if metrics.ConnectedSince.IsZero() {
			rows = append(rows, detailRow{label: l18n.Sprintf("Connected for"), value: l18n.Sprintf("not connected"), color: theme.textDim})
		} else {
			rows = append(rows, detailRow{label: l18n.Sprintf("Connected for"), value: formatDuration(now.Sub(metrics.ConnectedSince)), color: theme.green})
		}
		rate := currentRate(samples.seconds)
		rows = append(rows,
			detailRow{label: l18n.Sprintf("Receiving"), value: formatRate(rate.rx)},
			detailRow{label: l18n.Sprintf("Sending"), value: formatRate(rate.tx)},
		)
		if quality := summarizeQuality(samples.seconds); quality.hasData {
			rows = append(rows, qualityRows(quality)...)
		}
		rows = append(rows,
			detailRow{label: l18n.Sprintf("Interface errors"), value: l18n.Sprintf("%d in, %d out", metrics.InErrors, metrics.OutErrors), color: warnIf(metrics.InErrors+metrics.OutErrors > 0)},
			detailRow{label: l18n.Sprintf("Dropped packets"), value: l18n.Sprintf("%d in, %d out", metrics.InDiscards, metrics.OutDiscards), color: warnIf(metrics.InDiscards+metrics.OutDiscards > 0)},
		)
	}
	if entry.state == manager.TunnelStarted || metrics.ConnectionFailures+metrics.Reconnects > 0 {
		rows = append(rows,
			detailRow{label: l18n.Sprintf("Connection failures"), value: l18n.Sprintf("%d", metrics.ConnectionFailures), color: warnIf(metrics.ConnectionFailures > 0)},
			detailRow{label: l18n.Sprintf("Reconnects"), value: l18n.Sprintf("%d", metrics.Reconnects), color: warnIf(metrics.Reconnects > 0)},
		)
	}
	if !metrics.LastActiveEnd.IsZero() {
		rows = append(rows,
			detailRow{label: l18n.Sprintf("Last active"), value: formatAgo(now.Sub(metrics.LastActiveEnd))},
			detailRow{label: l18n.Sprintf("Last active for"), value: formatDuration(metrics.LastActiveDuration)},
		)
	}
	return rows
}

// qualityRows are latency, jitter and loss of the last minute.
func qualityRows(quality qualitySummary) []detailRow {
	if !quality.everAnswered {
		return []detailRow{{label: l18n.Sprintf("Latency"), value: l18n.Sprintf("no reply from the measured address"), color: theme.amberSoft}}
	}
	latency := detailRow{label: l18n.Sprintf("Latency"), value: l18n.Sprintf("no answer in the last minute"), color: theme.amberSoft}
	jitter := detailRow{label: l18n.Sprintf("Jitter"), value: l18n.Sprintf("unknown"), color: theme.textDim}
	if quality.answered {
		latency = detailRow{label: l18n.Sprintf("Latency"), value: formatLatency(quality.latency), color: warnIf(quality.latency >= poorQualityLatency)}
		jitter = detailRow{label: l18n.Sprintf("Jitter"), value: formatLatency(quality.jitter)}
	}
	loss := quality.lossPercent()
	return []detailRow{latency, jitter, {
		label: l18n.Sprintf("Loss"),
		value: l18n.Sprintf("%s (%d of %d in the last minute)", formatPercent(loss), quality.lost, quality.sent),
		color: warnIf(loss >= poorQualityLossPercent && quality.sent >= poorQualityMinProbes),
	}}
}

// warnIf is the color of a value that deserves attention when the condition holds.
func warnIf(condition bool) rgb {
	if condition {
		return theme.amberSoft
	}
	return 0
}
