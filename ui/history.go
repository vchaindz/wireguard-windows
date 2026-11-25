/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"encoding/csv"
	"io"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

const (
	// historyRefreshInterval is how often the history of the tunnel whose details are shown is fetched again. The
	// manager writes it once a minute, and the screen shows it in minutes.
	historyRefreshInterval = time.Minute
	// pathRefreshInterval is how often the path of the tunnel whose details are shown is fetched again.
	pathRefreshInterval = 10 * time.Second
	// sessionsShown is how many sessions the details screen lists before it offers to show all of them.
	sessionsShown = 8
	// usageChartDays is how many days the bar chart of the usage card shows, one bar per day.
	usageChartDays   = 30
	usageChartHeight = 124
	// uptimeDays is how far back uptime is computed, and uptimeMinActive how much active time those days need
	// before it is shown at all: with less, one short failure swings the figure, and it says little.
	uptimeDays      = 30
	uptimeMinActive = time.Hour
)

// dateKey numbers a calendar day, as written in the time's own zone, so that later days have larger numbers.
func dateKey(t time.Time) int {
	year, month, day := t.Date()
	return year*10000 + int(month)*100 + day
}

// usageTotals is what a tunnel did over some days.
type usageTotals struct {
	rx, tx            uint64
	active, connected time.Duration
}

// usageOfLastDays adds up the usage of the last count calendar days up to and including today. Days are compared
// by their dates, so that a day recorded in another time zone still counts as the day it was.
func usageOfLastDays(days []manager.TunnelDayUsage, now time.Time, count int) (totals usageTotals) {
	year, month, day := now.Date()
	first := dateKey(time.Date(year, month, day-(count-1), 12, 0, 0, 0, time.UTC))
	last := dateKey(time.Date(year, month, day, 12, 0, 0, 0, time.UTC))
	for i := range days {
		key := dateKey(days[i].Day)
		if key < first || key > last {
			continue
		}
		totals.rx += days[i].RxBytes
		totals.tx += days[i].TxBytes
		totals.active += time.Duration(days[i].ActiveSeconds) * time.Second
		totals.connected += time.Duration(days[i].ConnectedSeconds) * time.Second
	}
	return
}

// uptimePercent is the share of active time that was connected, and false if there was too little active time
// for the share to mean something.
func uptimePercent(totals usageTotals) (float64, bool) {
	if totals.active < uptimeMinActive {
		return 0, false
	}
	return min(float64(totals.connected)*100/float64(totals.active), 100), true
}

// lastDays returns the usage of each of the last count calendar days, oldest first and today last, with a zero
// record for a day without any, and whether each day has a record.
func lastDays(days []manager.TunnelDayUsage, now time.Time, count int) ([]manager.TunnelDayUsage, []bool) {
	year, month, day := now.Date()
	result := make([]manager.TunnelDayUsage, count)
	recorded := make([]bool, count)
	byKey := make(map[int]int, len(days))
	for i := range days {
		byKey[dateKey(days[i].Day)] = i
	}
	for i := range result {
		date := time.Date(year, month, day-(count-1-i), 0, 0, 0, 0, now.Location())
		result[i].Day = date
		if j, ok := byKey[dateKey(date)]; ok {
			result[i], recorded[i] = days[j], true
			result[i].Day = date
		}
	}
	return result, recorded
}

// usageChart is the bar chart of the data received, drawn upwards, and sent, drawn downwards, on each of the last
// days, like the traffic graph.
func usageChart(id string, days []manager.TunnelDayUsage, now time.Time) *chart {
	recent, recorded := lastDays(days, now, usageChartDays)
	buckets := make([]chartBucket, len(recent))
	for i := range recent {
		if recorded[i] {
			buckets[i].value = [2]float64{float64(recent[i].RxBytes), float64(recent[i].TxBytes)}
			buckets[i].has = [2]bool{true, true}
		}
	}
	formatAmount := func(bytes float64) string { return formatBytes(uint64(max(bytes, 0))) }
	return &chart{
		id:      id,
		caption: l18n.Sprintf("Last %d days", usageChartDays),
		height:  usageChartHeight,
		series:  []chartSeries{{theme.green, theme.greenFill}, {theme.blue, theme.blueFill}},
		mirror:  true,
		bars:    true,
		buckets: buckets,
		end:     now,
		span:    usageChartDays * 24 * time.Hour,
		minPeak: 1024 * 1024,
		format:  formatAmount,
		hoverCaption: func(index int) string {
			day := formatDay(recent[index].Day, now)
			if recent[index].ActiveSeconds == 0 {
				return day
			}
			return l18n.Sprintf("%s · active %s", day, formatDuration(time.Duration(recent[index].ActiveSeconds)*time.Second))
		},
		axisText: func(fraction float64) string {
			return formatDay(recent[min(int(fraction*float64(len(recent))), len(recent)-1)].Day, now)
		},
		legend: func(bucket *chartBucket) []chartLegend {
			if bucket == nil {
				return []chartLegend{{theme.green, l18n.Sprintf("Received")}, {theme.blue, l18n.Sprintf("Sent")}}
			}
			rx, tx := "–", "–"
			if bucket.has[0] {
				rx, tx = formatAmount(bucket.value[0]), formatAmount(bucket.value[1])
			}
			return []chartLegend{{theme.green, l18n.Sprintf("In %s", rx)}, {theme.blue, l18n.Sprintf("Out %s", tx)}}
		},
	}
}

// sessionEndText says in plain words how a session ended.
func sessionEndText(end manager.SessionEnd) string {
	switch end {
	case manager.SessionInProgress:
		return l18n.Sprintf("in progress")
	case manager.SessionDeactivated:
		return l18n.Sprintf("deactivated")
	case manager.SessionManagerStopped:
		return l18n.Sprintf("WireGuard service stopped")
	case manager.SessionSuspended:
		return l18n.Sprintf("computer went to sleep")
	}
	return l18n.Sprintf("unknown")
}

// sessionEndKey is how the export names how a session ended: fixed words, for programs to read.
func sessionEndKey(end manager.SessionEnd) string {
	switch end {
	case manager.SessionInProgress:
		return "in_progress"
	case manager.SessionDeactivated:
		return "deactivated"
	case manager.SessionManagerStopped:
		return "manager_stopped"
	case manager.SessionSuspended:
		return "suspended"
	}
	return "unknown"
}

// writeHistoryCSV writes the history as one CSV file of two tables, each with a header row: the sessions, oldest
// first, then after an empty line the usage per day. Times are ISO 8601 with the offset they were recorded in,
// days are dates, and amounts are plain integers, so that spreadsheets and scripts read them without guessing.
// The headers are not translated, for the same reason.
func writeHistoryCSV(w io.Writer, history manager.TunnelHistory) error {
	out := csv.NewWriter(w)
	out.UseCRLF = true
	u32 := func(v uint32) string { return strconv.FormatUint(uint64(v), 10) }
	u64 := func(v uint64) string { return strconv.FormatUint(v, 10) }
	out.Write([]string{"session_start", "session_end", "active_seconds", "connected_seconds", "received_bytes", "sent_bytes", "connection_failures", "reconnects", "endpoint", "ended_by"})
	for _, session := range history.Sessions {
		out.Write([]string{
			session.Start.Format(time.RFC3339), session.End.Format(time.RFC3339),
			u32(session.ActiveSeconds), u32(session.ConnectedSeconds),
			u64(session.RxBytes), u64(session.TxBytes),
			u32(session.ConnectionFailures), u32(session.Reconnects),
			session.Endpoint, sessionEndKey(session.EndedBy),
		})
	}
	out.Write(nil)
	out.Write([]string{"day", "received_bytes", "sent_bytes", "active_seconds", "connected_seconds"})
	for _, day := range history.Days {
		out.Write([]string{day.Day.Format("2006-01-02"), u64(day.RxBytes), u64(day.TxBytes), u32(day.ActiveSeconds), u32(day.ConnectedSeconds)})
	}
	out.Flush()
	return out.Error()
}

// historySection draws the usage and the sessions of a tunnel on its details screen, or a line saying that
// policy disables history, and returns its height. It draws nothing until the history has been loaded.
func (mtw *ManageTunnelsWindow) historySection(s *scene, x, y, w float64, entry *tunnelEntry, now time.Time) float64 {
	const pad = 16
	if !entry.historyLoaded {
		return 0
	}
	if !entry.historyEnabled {
		s.fill(x, y, w, 44, 8, theme.panel)
		s.label(l18n.Sprintf("Connection history is disabled by policy."), fontBody, theme.textDim, x+pad, y, w-2*pad, 44, textLeft)
		return 44
	}
	history := &entry.history
	if len(history.Sessions) == 0 && len(history.Days) == 0 {
		text := l18n.Sprintf("Nothing recorded yet. Usage and sessions show up here once the tunnel has been active.")
		textHeight := s.wrappedHeight(text, fontBody, w-2*pad)
		height := pad + 16 + 10 + textHeight + pad
		s.fill(x, y, w, height, 8, theme.panel)
		s.label(l18n.Sprintf("HISTORY"), fontCaps, theme.textDim, x+pad, y+pad, w-2*pad, 16, textLeft)
		s.text(text, fontBody, theme.textDim, x+pad, y+pad+16+10, w-2*pad, textHeight, textWrap)
		return height
	}
	top := y
	y += mtw.usageCard(s, x, y, w, history, now) + 14
	y += mtw.sessionsCard(s, x, y, w, entry, now)
	return y - top
}

// usageCard draws the totals of today, the last week and the last month, the uptime, and the bar chart of the
// last days, and returns its height.
func (mtw *ManageTunnelsWindow) usageCard(s *scene, x, y, w float64, history *manager.TunnelHistory, now time.Time) float64 {
	const pad, labelWidth, rowHeight = 16, 104, 24
	columnWidth := (w - 2*pad - labelWidth) / 3
	rows := []struct {
		label  string
		totals usageTotals
	}{
		{l18n.Sprintf("Today"), usageOfLastDays(history.Days, now, 1)},
		{l18n.Sprintf("Last 7 days"), usageOfLastDays(history.Days, now, 7)},
		{l18n.Sprintf("Last 30 days"), usageOfLastDays(history.Days, now, 30)},
	}
	uptimeText := ""
	if percent, ok := uptimePercent(usageOfLastDays(history.Days, now, uptimeDays)); ok {
		uptimeText = l18n.Sprintf("%s of active time connected, over the last %d days", formatPercent(percent), uptimeDays)
	}
	uptimeHeight := 0.0
	if len(uptimeText) > 0 {
		uptimeHeight = max(s.wrappedHeight(uptimeText, fontBody, w-2*pad-labelWidth), 20) + 6
	}
	height := pad + 16 + 10 + 22 + float64(len(rows))*rowHeight + uptimeHeight + 10 + usageChartHeight + 4

	s.fill(x, y, w, height, 8, theme.panel)
	s.label(l18n.Sprintf("USAGE"), fontCaps, theme.textDim, x+pad, y+pad, w-2*pad, 16, textLeft)
	rowY := y + pad + 16 + 10
	columns := [3]string{l18n.Sprintf("Received"), l18n.Sprintf("Sent"), l18n.Sprintf("Active")}
	for i, caption := range columns {
		s.label(caption, fontSmall, theme.textDim, x+pad+labelWidth+float64(i)*columnWidth, rowY, columnWidth-4, 18, textRight)
	}
	rowY += 22
	for _, row := range rows {
		s.label(row.label, fontBody, theme.textDim, x+pad, rowY, labelWidth-8, 20, textLeft)
		values := [3]string{formatBytes(row.totals.rx), formatBytes(row.totals.tx), formatDuration(row.totals.active)}
		for i, value := range values {
			s.label(value, fontBody, theme.text, x+pad+labelWidth+float64(i)*columnWidth, rowY, columnWidth-4, 20, textRight)
		}
		rowY += rowHeight
	}
	if len(uptimeText) > 0 {
		rowY += 6
		s.label(l18n.Sprintf("Uptime"), fontBody, theme.textDim, x+pad, rowY, labelWidth-8, 20, textLeft)
		s.text(uptimeText, fontBody, theme.text, x+pad+labelWidth, rowY+1, w-2*pad-labelWidth, uptimeHeight-6, textWrap)
		rowY += uptimeHeight - 6
	}
	rowY += 10
	// The chart has a padding of its own; drawn a little inside the card, its caption lines up with the title.
	s.chart(x+4, rowY, w-8, usageChart("chart:usage", history.Days, now))
	return height
}

// sessionsCard draws the most recent sessions, newest first, with the choice to show all of them, and the
// buttons to save and to clear the history. It returns its height.
func (mtw *ManageTunnelsWindow) sessionsCard(s *scene, x, y, w float64, entry *tunnelEntry, now time.Time) float64 {
	const pad, rowHeight, buttonHeight = 16, 48, 36
	model, name := mtw.model, entry.tunnel.Name
	sessions := entry.history.Sessions
	shown := len(sessions)
	if !mtw.historyExpanded {
		shown = min(shown, sessionsShown)
	}
	height := pad + 16 + 6 + float64(shown)*rowHeight
	if len(sessions) > sessionsShown {
		height += 6 + buttonHeight
	}
	height += 12 + buttonHeight + pad

	s.fill(x, y, w, height, 8, theme.panel)
	s.label(l18n.Sprintf("SESSIONS"), fontCaps, theme.textDim, x+pad, y+pad, w-2*pad, 16, textLeft)
	rowY := y + pad + 16 + 6
	for i := 0; i < shown; i++ {
		session := &sessions[len(sessions)-1-i]
		if i > 0 {
			s.fill(x+pad, rowY, w-2*pad, 1, 0, theme.line)
		}
		data := l18n.Sprintf("%s · %s", l18n.Sprintf("In %s", formatBytes(session.RxBytes)), l18n.Sprintf("Out %s", formatBytes(session.TxBytes)))
		dataWidth := min(s.widthOf(data, fontBody)+2, (w-2*pad)/2)
		s.label(formatDayAndClock(session.Start, now), fontBody, theme.text, x+pad, rowY+6, w-2*pad-dataWidth-8, 20, textLeft)
		s.label(data, fontBody, theme.text, x+w-pad-dataWidth, rowY+6, dataWidth, 20, textRight)
		ending, color := sessionEndText(session.EndedBy), theme.textDim
		if session.EndedBy == manager.SessionInProgress {
			color = theme.green
		}
		duration := formatDuration(time.Duration(session.ActiveSeconds) * time.Second)
		s.label(l18n.Sprintf("%s · %s", duration, ending), fontSmall, color, x+pad, rowY+26, w-2*pad, 18, textLeft)
		rowY += rowHeight
	}
	if len(sessions) > sessionsShown {
		rowY += 6
		label := l18n.Sprintf("Show all %d sessions", len(sessions))
		if mtw.historyExpanded {
			label = l18n.Sprintf("Show fewer")
		}
		s.button("history-more", x+pad, rowY, w-2*pad, buttonHeight, label, buttonFlat, mtw.toggleHistoryExpanded)
		rowY += buttonHeight
	}
	rowY += 12
	// Saving is offered to everyone who can see the history; clearing it only to administrators.
	saveWidth := w - 2*pad
	if IsAdmin {
		saveWidth = (w - 2*pad - 8) / 2
	}
	s.button("history-save", x+pad, rowY, saveWidth, buttonHeight, l18n.Sprintf("Save history…"), buttonOutline, func() { model.saveHistory(mtw, name) })
	if IsAdmin {
		s.button("history-clear", x+pad+saveWidth+8, rowY, saveWidth, buttonHeight, l18n.Sprintf("Clear history"), buttonDanger, func() { model.clearHistory(mtw, name) })
	}
	return height
}

// toggleHistoryExpanded shows all sessions instead of the most recent ones, or the most recent ones again.
func (mtw *ManageTunnelsWindow) toggleHistoryExpanded() {
	mtw.historyExpanded = !mtw.historyExpanded
	if mtw.mainView != nil {
		mtw.mainView.Invalidate()
	}
}
