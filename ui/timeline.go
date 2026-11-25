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

// The events timeline is a strip under the graphs that shows the state of a tunnel over their time range as
// colored stretches, with marks for handshakes, reconnects and lost probes. A connection that keeps dropping, or
// a key that another device uses, shows there as a pattern that a single state or counter does not.

// timelineState is what the strip shows for a stretch of time. The states are ordered by how much they need
// attention, so that a stretch too short to draw on its own gives way to the worse of its neighbors.
type timelineState int

const (
	timelineNoData timelineState = iota
	timelineConnected
	timelineUnverified
	timelineWaiting
	timelineNoConnection
	timelineCutOff
	timelineStateCount
)

func timelineStateOf(health manager.TunnelHealth) timelineState {
	switch health {
	case manager.TunnelHealthConnected:
		return timelineConnected
	case manager.TunnelHealthUnverified:
		return timelineUnverified
	case manager.TunnelHealthWaitingForPeer:
		return timelineWaiting
	case manager.TunnelHealthNoConnection:
		return timelineNoConnection
	case manager.TunnelHealthNoConnectionNetworkBlocked:
		return timelineCutOff
	}
	return timelineNoData
}

func (state timelineState) name() string {
	switch state {
	case timelineConnected:
		return l18n.Sprintf("Connected")
	case timelineUnverified:
		return l18n.Sprintf("Not verified")
	case timelineWaiting:
		return l18n.Sprintf("Waiting for peer")
	case timelineNoConnection:
		return l18n.Sprintf("No connection")
	case timelineCutOff:
		return l18n.Sprintf("Network cut off")
	}
	return l18n.Sprintf("No data")
}

func (state timelineState) color() rgb {
	switch state {
	case timelineConnected:
		return theme.green
	case timelineUnverified:
		return theme.muted
	case timelineWaiting:
		return theme.amberBorder
	case timelineNoConnection:
		return theme.amber
	case timelineCutOff:
		return theme.red
	}
	return theme.line
}

// bandHeight is how tall a stretch in the state is drawn in a band of the given height. Besides its color, the
// height tells the states apart, which matters where a high-contrast scheme leaves few colors: no data is a thin
// line, an unverified connection half the band, and the rest all of it.
func (state timelineState) bandHeight(full float64) float64 {
	switch state {
	case timelineNoData:
		return 2
	case timelineUnverified:
		return full / 2
	}
	return full
}

// A timelineSegment is a stretch of time in one state.
type timelineSegment struct {
	start, end time.Time
	state      timelineState
}

// healthSegments turns samples into the stretches of state that cover the time from start to end. Each sample
// stands for the time until the next one; consecutive samples of equal health merge into one stretch. Where the
// next sample is more than maxGap later, or the newest one is that far before end, the sample covers only a third
// of maxGap, about one sampling interval, and the rest is a stretch of no data. The stretches are in order, do not
// overlap, and cover the whole time.
func healthSegments(samples []manager.TunnelSample, start, end time.Time, maxGap time.Duration) []timelineSegment {
	var segments []timelineSegment
	if !end.After(start) {
		return nil
	}
	push := func(from, to time.Time, state timelineState) {
		if n := len(segments); n > 0 && segments[n-1].state == state && !segments[n-1].end.Before(from) {
			segments[n-1].end = to
			return
		}
		segments = append(segments, timelineSegment{from, to, state})
	}
	add := func(from, to time.Time, state timelineState) {
		if from.Before(start) {
			from = start
		}
		if to.After(end) {
			to = end
		}
		cursor := start
		if n := len(segments); n > 0 {
			cursor = segments[n-1].end
		}
		if from.Before(cursor) {
			from = cursor
		}
		if !to.After(from) {
			return
		}
		if from.After(cursor) {
			push(cursor, from, timelineNoData)
		}
		push(from, to, state)
	}
	for i := range samples {
		at := samples[i].Time
		if at.After(end) {
			break
		}
		to := at.Add(maxGap / 3)
		if i+1 < len(samples) {
			if next := samples[i+1].Time; next.Sub(at) <= maxGap {
				to = next
			}
		} else if end.Sub(at) <= maxGap {
			to = end
		}
		add(at, to, timelineStateOf(samples[i].Health))
	}
	if n := len(segments); n == 0 || segments[n-1].end.Before(end) {
		from := start
		if n > 0 {
			from = segments[n-1].end
		}
		push(from, end, timelineNoData)
	}
	return segments
}

// timelineColumns is the state to draw in each of a number of columns of equal width spanning span from start:
// the worst state that any stretch in the column has, so that a short loss stays visible however long the range.
func timelineColumns(segments []timelineSegment, start time.Time, span time.Duration, columns int) []timelineState {
	states := make([]timelineState, max(columns, 0))
	if columns <= 0 || span <= 0 {
		return states
	}
	for _, segment := range segments {
		first := int(math.Floor(float64(segment.start.Sub(start)) * float64(columns) / float64(span)))
		last := int(math.Ceil(float64(segment.end.Sub(start)) * float64(columns) / float64(span)))
		for i := max(first, 0); i < min(last, columns); i++ {
			if segment.state > states[i] {
				states[i] = segment.state
			}
		}
	}
	return states
}

// worstStateBetween is the worst state of the stretches that overlap the time from start to end.
func worstStateBetween(segments []timelineSegment, start, end time.Time) timelineState {
	worst := timelineNoData
	for _, segment := range segments {
		if segment.end.After(start) && segment.start.Before(end) && segment.state > worst {
			worst = segment.state
		}
	}
	return worst
}

// A timelineBucket counts what happened in one slot of the strip.
type timelineBucket struct {
	handshakes, reconnects int
	sent, lost             int
	conflict, unstable     bool
}

// timelineBuckets sorts the events of samples into count slots of equal length starting at start and spanning
// span. A reconnect is a sample that finds the tunnel connected right after one that found it without a
// connection; samples further apart than maxGap do not follow each other.
func timelineBuckets(samples []manager.TunnelSample, start time.Time, span time.Duration, count int, maxGap time.Duration) []timelineBucket {
	buckets := make([]timelineBucket, max(count, 0))
	if count <= 0 || span <= 0 {
		return buckets
	}
	for i := range samples {
		sample := &samples[i]
		offset := sample.Time.Sub(start)
		if offset < 0 || offset > span {
			continue
		}
		index := min(int(int64(offset)*int64(count)/int64(span)), count-1)
		bucket := &buckets[index]
		bucket.handshakes += int(sample.Handshakes)
		if sample.Probed {
			bucket.sent += int(sample.ProbesSent)
			bucket.lost += int(sample.ProbesLost)
		}
		bucket.conflict = bucket.conflict || sample.ConflictSuspected
		bucket.unstable = bucket.unstable || sample.Unstable
		if i > 0 && sample.Health == manager.TunnelHealthConnected && samples[i-1].Health.IsNoConnection() && sample.Time.Sub(samples[i-1].Time) <= maxGap {
			bucket.reconnects++
		}
	}
	return buckets
}

// timelineMaxGap is how far apart samples may be before the time between them counts as no data: a few sampling
// intervals, which are a second or five while the window is open or closed, and a minute for the day.
func timelineMaxGap(samples tunnelSamples, r chartRange) time.Duration {
	if r == rangeDay && len(samples.minutes) > 0 {
		return 3 * time.Minute
	}
	return 16 * time.Second
}

// A timelineLegendItem is one entry of the legend: a swatch drawn by kind, and what it means.
type timelineLegendItem struct {
	kind  int // 0 a stretch of state, 1 a mark, 2 a warning bar
	color rgb
	text  string
}

const (
	timelinePad       = 12
	timelineCaption   = 18
	timelineBandTop   = 38
	timelineBand      = 16
	timelineWarnTop   = 32
	timelineMarksTop  = 58
	timelineAxisTop   = 76
	timelineLegendTop = 98
	timelineLegendRow = 18
)

// timeline draws the strip of events of a tunnel over the time range of the graphs, ending at end, with its plot
// starting gutter in from the padding so that it lines up with the graphs above, and returns its height.
func (s *scene) timeline(id string, x, y, w, gutter float64, samples tunnelSamples, r chartRange, end time.Time) float64 {
	source := rangeSamples(samples, r)
	span := r.span()
	start := end.Add(-span)
	maxGap := timelineMaxGap(samples, r)
	segments := healthSegments(source, start, end, maxGap)
	count := r.buckets()
	buckets := timelineBuckets(source, start, span, count, maxGap)

	plotX, plotWidth := x+timelinePad+gutter, w-2*timelinePad-gutter
	columns := timelineColumns(segments, start, span, max(int(plotWidth/2), 1))

	// What occurs in the range decides the legend, which keeps it short.
	var seen [timelineStateCount]bool
	for _, state := range columns {
		seen[state] = true
	}
	var handshakes, reconnects, lost int
	var conflict, unstable bool
	for i := range buckets {
		handshakes += buckets[i].handshakes
		reconnects += buckets[i].reconnects
		lost += buckets[i].lost
		conflict = conflict || buckets[i].conflict
		unstable = unstable || buckets[i].unstable
	}
	var legend []timelineLegendItem
	for state := timelineConnected; state < timelineStateCount; state++ {
		if seen[state] {
			legend = append(legend, timelineLegendItem{0, state.color(), state.name()})
		}
	}
	if seen[timelineNoData] {
		legend = append(legend, timelineLegendItem{0, timelineNoData.color(), timelineNoData.name()})
	}
	if handshakes > 0 {
		legend = append(legend, timelineLegendItem{1, theme.textDim, l18n.Sprintf("Handshake")})
	}
	if reconnects > 0 {
		legend = append(legend, timelineLegendItem{1, theme.blue, l18n.Sprintf("Reconnect")})
	}
	if lost > 0 {
		legend = append(legend, timelineLegendItem{1, theme.red, l18n.Sprintf("Lost probe")})
	}
	if conflict {
		legend = append(legend, timelineLegendItem{2, theme.redSoft, l18n.Sprintf("Key used elsewhere")})
	}
	if unstable {
		legend = append(legend, timelineLegendItem{2, theme.amberSoft, l18n.Sprintf("Unstable")})
	}
	// The legend flows into as many rows as it needs.
	legendX, legendRows := make([]float64, len(legend)), make([]int, len(legend))
	rowX, row, room := 0.0, 0, w-2*timelinePad
	for i := range legend {
		itemWidth := 14 + s.widthOf(legend[i].text, fontSmall)
		if rowX > 0 && rowX+itemWidth > room {
			rowX, row = 0, row+1
		}
		legendX[i], legendRows[i] = rowX, row
		rowX += itemWidth + 14
	}
	height := float64(timelineLegendTop + 8)
	if len(legend) > 0 {
		height += float64(row+1) * timelineLegendRow
	}

	s.fill(x, y, w, height, 8, theme.panel)

	// The caption, or what is under the mouse, and a count of the events in the range.
	hovered := -1
	if s.hover(id, plotX, y+timelineWarnTop-4, plotWidth, timelineAxisTop-timelineWarnTop+4) {
		hovered = chartSlot(s.mouseX, plotX, plotWidth, count)
	}
	caption, captionColor := l18n.Sprintf("Events"), theme.textDim
	if hovered >= 0 {
		from := start.Add(time.Duration(hovered) * span / time.Duration(count))
		to := start.Add(time.Duration(hovered+1) * span / time.Duration(count))
		caption = l18n.Sprintf("%s · %s", from.Add(to.Sub(from)/2).Format(r.timeFormat()), worstStateBetween(segments, from, to).name())
		bucket := &buckets[hovered]
		if bucket.reconnects > 0 {
			caption = l18n.Sprintf("%s · %s", caption, l18n.Sprintf("%d reconnects", bucket.reconnects))
		}
		if bucket.handshakes > 0 {
			caption = l18n.Sprintf("%s · %s", caption, l18n.Sprintf("%d handshakes", bucket.handshakes))
		}
		if bucket.lost > 0 {
			caption = l18n.Sprintf("%s · %s", caption, l18n.Sprintf("%d of %d probes lost", bucket.lost, bucket.sent))
		}
		if bucket.conflict {
			caption = l18n.Sprintf("%s · %s", caption, l18n.Sprintf("Key used elsewhere"))
		} else if bucket.unstable {
			caption = l18n.Sprintf("%s · %s", caption, l18n.Sprintf("Unstable"))
		}
		captionColor = theme.text
	}
	summary := ""
	if hovered < 0 {
		summary = l18n.Sprintf("%d reconnects · %d handshakes", reconnects, handshakes)
	}
	summaryWidth := 0.0
	if len(summary) > 0 {
		summaryWidth = s.widthOf(summary, fontSmall) + 2
		s.label(summary, fontSmall, theme.textDim, x+w-timelinePad-summaryWidth, y+8, summaryWidth, timelineCaption, textRight)
	}
	s.label(caption, fontSmall, captionColor, x+timelinePad, y+8, w-2*timelinePad-summaryWidth-8, timelineCaption, textLeft)

	// The stretches of state, as runs of columns of equal state, each drawn from the bottom of the band.
	columnWidth := plotWidth / float64(len(columns))
	bandBottom := y + timelineBandTop + timelineBand
	for first := 0; first < len(columns); {
		last := first
		for last+1 < len(columns) && columns[last+1] == columns[first] {
			last++
		}
		state := columns[first]
		bandHeight := state.bandHeight(timelineBand)
		s.fill(plotX+float64(first)*columnWidth, bandBottom-bandHeight, float64(last-first+1)*columnWidth, bandHeight, 0, state.color())
		first = last + 1
	}

	// Warnings as a thin bar over the band, marks under it: handshakes on the first row, reconnects and lost
	// probes on the second.
	slot := plotWidth / float64(count)
	for i := range buckets {
		bucket := &buckets[i]
		slotX := plotX + float64(i)*slot
		switch {
		case bucket.conflict:
			s.fill(slotX, y+timelineWarnTop, slot, 3, 0, theme.redSoft)
		case bucket.unstable:
			s.fill(slotX, y+timelineWarnTop, slot, 3, 0, theme.amberSoft)
		}
		markX := slotX + slot/2 - 1
		if bucket.handshakes > 0 {
			tick := math.Min(3+1.5*float64(bucket.handshakes), 8)
			s.fill(markX, y+timelineMarksTop, 2, tick, 1, theme.textDim)
		}
		if bucket.reconnects > 0 {
			s.poly(theme.blue, markX+1, y+timelineMarksTop+9, markX+5, y+timelineMarksTop+16, markX-3, y+timelineMarksTop+16)
		} else if bucket.lost > 0 {
			s.fill(markX, y+timelineMarksTop+9, 2, 4+4*math.Min(float64(bucket.lost)/float64(max(bucket.sent, 1)), 1), 1, theme.red)
		}
	}
	if hovered >= 0 {
		s.fill(plotX+(float64(hovered)+0.5)*slot-0.5, y+timelineWarnTop-2, 1, timelineAxisTop-timelineWarnTop, 0, theme.textDim)
	}

	s.timeAxis(plotX, plotWidth, y+timelineAxisTop, 16, span, nil)

	for i, item := range legend {
		itemX, itemY := x+timelinePad+legendX[i], y+timelineLegendTop+float64(legendRows[i])*timelineLegendRow
		switch item.kind {
		case 0:
			s.fill(itemX, itemY+4, 10, 10, 2, item.color)
		case 1:
			s.fill(itemX+4, itemY+3, 2, 12, 1, item.color)
		default:
			s.fill(itemX, itemY+7.5, 10, 3, 0, item.color)
		}
		s.label(item.text, fontSmall, theme.text, itemX+14, itemY, s.widthOf(item.text, fontSmall)+2, timelineLegendRow, textLeft)
	}
	return height
}
