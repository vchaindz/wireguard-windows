/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// trafficHistoryLength is how many samples of the traffic rate are kept: one per second of the
// last minute while the window is shown.
const trafficHistoryLength = 60

// A trafficSample is the traffic rate at one moment, in bytes per second.
type trafficSample struct {
	rx, tx float64
}

// A trafficHistory turns the byte counters of a tunnel into rates.
type trafficHistory struct {
	lastRx, lastTx conf.Bytes
	lastAt         time.Time
	samples        []trafficSample
}

// record takes note of the counters at a time. Counters that go backwards mean the tunnel was
// restarted, and samples that follow each other too closely are skipped, as their rate would be noise.
func (history *trafficHistory) record(now time.Time, rx, tx conf.Bytes) {
	if history.lastAt.IsZero() || rx < history.lastRx || tx < history.lastTx {
		history.lastRx, history.lastTx, history.lastAt, history.samples = rx, tx, now, nil
		return
	}
	elapsed := now.Sub(history.lastAt).Seconds()
	if elapsed < 0.5 {
		return
	}
	history.samples = append(history.samples, trafficSample{float64(rx-history.lastRx) / elapsed, float64(tx-history.lastTx) / elapsed})
	if len(history.samples) > trafficHistoryLength {
		history.samples = history.samples[len(history.samples)-trafficHistoryLength:]
	}
	history.lastRx, history.lastTx, history.lastAt = rx, tx, now
}

// current is the most recent rate.
func (history *trafficHistory) current() trafficSample {
	if history == nil || len(history.samples) == 0 {
		return trafficSample{}
	}
	return history.samples[len(history.samples)-1]
}

// peak is the highest rate in either direction that the history holds.
func (history *trafficHistory) peak() (peak float64) {
	if history == nil {
		return 0
	}
	for _, sample := range history.samples {
		if sample.rx > peak {
			peak = sample.rx
		}
		if sample.tx > peak {
			peak = sample.tx
		}
	}
	return
}

func formatRate(bytesPerSecond float64) string {
	return l18n.Sprintf("%s/s", conf.Bytes(bytesPerSecond+0.5).String())
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
	return l18n.Sprintf("last active %s ago for %s", formatDuration(now.Sub(metrics.LastActiveEnd)), formatDuration(metrics.LastActiveDuration))
}

// connectionRows are the metrics of a tunnel as shown on its details screen.
func connectionRows(entry *tunnelEntry, history *trafficHistory, now time.Time) []detailRow {
	metrics := &entry.metrics
	var rows []detailRow
	if entry.state == manager.TunnelStarted && !metrics.ActiveSince.IsZero() {
		rows = append(rows, detailRow{label: l18n.Sprintf("Active for"), value: formatDuration(now.Sub(metrics.ActiveSince))})
		if metrics.ConnectedSince.IsZero() {
			rows = append(rows, detailRow{label: l18n.Sprintf("Connected for"), value: l18n.Sprintf("not connected"), color: themeTextDim})
		} else {
			rows = append(rows, detailRow{label: l18n.Sprintf("Connected for"), value: formatDuration(now.Sub(metrics.ConnectedSince)), color: themeGreen})
		}
		rate := history.current()
		rows = append(rows,
			detailRow{label: l18n.Sprintf("Receiving"), value: formatRate(rate.rx)},
			detailRow{label: l18n.Sprintf("Sending"), value: formatRate(rate.tx)},
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
			detailRow{label: l18n.Sprintf("Last active"), value: l18n.Sprintf("%s ago", formatDuration(now.Sub(metrics.LastActiveEnd)))},
			detailRow{label: l18n.Sprintf("Last active for"), value: formatDuration(metrics.LastActiveDuration)},
		)
	}
	return rows
}

// warnIf is the color of a value that deserves attention when the condition holds.
func warnIf(condition bool) rgb {
	if condition {
		return themeAmberSoft
	}
	return 0
}

// trafficGraph draws the traffic of the last minute: what was received as bars above a middle
// line, what was sent below it, both to the scale of the highest rate. It returns its height.
func (s *scene) trafficGraph(x, y, w float64, history *trafficHistory) float64 {
	const height, pad, captionHeight = 96, 12, 18
	s.fill(x, y, w, height, 8, themePanel)
	s.label(l18n.Sprintf("Last 60 seconds"), fontSmall, themeTextDim, x+pad, y+8, w/2, captionHeight, textLeft)
	rate := history.current()
	legendWidth := (w/2 - pad) / 2
	s.fill(x+w/2, y+13, 8, 8, 4, themeGreen)
	s.label(l18n.Sprintf("In %s", formatRate(rate.rx)), fontSmall, themeText, x+w/2+12, y+8, legendWidth-12, captionHeight, textLeft)
	s.fill(x+w/2+legendWidth, y+13, 8, 8, 4, themeBlue)
	s.label(l18n.Sprintf("Out %s", formatRate(rate.tx)), fontSmall, themeText, x+w/2+legendWidth+12, y+8, legendWidth-12, captionHeight, textLeft)

	plotTop := y + 8 + captionHeight + 6
	half := (y + height - pad - plotTop) / 2
	middle := plotTop + half
	s.fill(x+pad, middle-0.5, w-2*pad, 1, 0, themeLine)
	if history == nil || len(history.samples) == 0 {
		return height
	}
	peak := history.peak()
	if peak < 1024 {
		peak = 1024
	}
	slot := (w - 2*pad) / trafficHistoryLength
	barWidth := slot - 1
	if barWidth < 1.5 {
		barWidth = slot
	}
	// The newest sample is at the right edge.
	first := trafficHistoryLength - len(history.samples)
	for i, sample := range history.samples {
		barX := x + pad + float64(first+i)*slot
		if up := sample.rx / peak * (half - 1); up >= 0.5 {
			s.fill(barX, middle-0.5-up, barWidth, up, 1, themeGreen)
		}
		if down := sample.tx / peak * (half - 1); down >= 0.5 {
			s.fill(barX, middle+0.5, barWidth, down, 1, themeBlue)
		}
	}
	return height
}
