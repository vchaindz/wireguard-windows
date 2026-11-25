/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"math"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// A chartRange is how far back the graphs look.
type chartRange int

const (
	rangeMinute chartRange = iota
	rangeHour
	rangeDay
	chartRangeCount
)

func (r chartRange) span() time.Duration {
	switch r {
	case rangeHour:
		return time.Hour
	case rangeDay:
		return 24 * time.Hour
	}
	return time.Minute
}

// buckets is how many points a chart of the range has. A minute has one per second; longer ranges are
// summarised, so that drawing costs the same whatever the range.
func (r chartRange) buckets() int {
	if r == rangeMinute {
		return 60
	}
	return 120
}

func (r chartRange) label() string {
	switch r {
	case rangeHour:
		return l18n.Sprintf("1 h")
	case rangeDay:
		return l18n.Sprintf("24 h")
	}
	return l18n.Sprintf("1 min")
}

// timeFormat is how the time under the mouse is written.
func (r chartRange) timeFormat() string {
	if r == rangeDay {
		return "15:04"
	}
	return "15:04:05"
}

// rangeSamples are the samples that a chart of the range is drawn from. The day uses the per-minute samples,
// followed by the per-second ones of the minute that is still running, or all of them while the per-minute
// samples have not arrived yet.
func rangeSamples(samples tunnelSamples, r chartRange) []manager.TunnelSample {
	if r != rangeDay || len(samples.minutes) == 0 {
		return samples.seconds
	}
	merged := endStamped(samples.minutes)
	last := merged[len(merged)-1].Time
	for i := range samples.seconds {
		if samples.seconds[i].Time.After(last) {
			merged = append(merged, samples.seconds[i:]...)
			break
		}
	}
	return merged
}

// trafficBuckets are the traffic rates of the range ending at end.
func trafficBuckets(samples tunnelSamples, r chartRange, end time.Time) []chartBucket {
	return bucketPoints(ratePoints(deriveRates(rangeSamples(samples, r))), end.Add(-r.span()), r.span(), r.buckets())
}

// latencyBuckets are the probe results of the range ending at end, or nil if there are none.
func latencyBuckets(samples tunnelSamples, r chartRange, end time.Time) []chartBucket {
	source := rangeSamples(samples, r)
	if !anyProbed(source, end.Add(-r.span()), end) {
		return nil
	}
	return bucketPoints(latencyPoints(source), end.Add(-r.span()), r.span(), r.buckets())
}

// A chartLegend is one entry of the legend: a colored dot and a text.
type chartLegend struct {
	color rgb
	text  string
}

type chartSeries struct {
	color, fill rgb
}

// A chart describes a graph of one or two series over a time range.
type chart struct {
	// id names the region that follows the mouse.
	id      string
	caption string
	height  float64
	series  []chartSeries
	// mirror draws the second series downwards from a middle line instead of both upwards.
	mirror  bool
	buckets []chartBucket
	end     time.Time
	span    time.Duration
	// timeFormat is how the time under the mouse is written.
	timeFormat string
	bars       bool
	// lossMarks shows the lost probes of each bucket as red marks on the baseline.
	lossMarks bool
	// minPeak keeps small values from filling the whole height.
	minPeak float64
	// format writes a value, for the scale.
	format func(float64) string
	// legend is what the legend says about a bucket, or about the current values if bucket is nil.
	legend func(bucket *chartBucket) []chartLegend
	// minGutter widens the room for the scale, so that the plots of charts drawn one above the other line up.
	minGutter float64
	// hoverCaption, if set, is what the caption says over a bucket, instead of its time in timeFormat.
	hoverCaption func(index int) string
	// axisText, if set, writes the label of the time axis at a fraction of its width, instead of how long ago that
	// point is.
	axisText func(fraction float64) string
}

// peak is the highest value the chart shows, which is the top of its scale.
func (c *chart) peak() float64 {
	peak := c.minPeak
	for i := range c.buckets {
		for series := range c.series {
			if c.buckets[i].has[series] && c.buckets[i].value[series] > peak {
				peak = c.buckets[i].value[series]
			}
		}
	}
	if peak <= 0 {
		peak = 1
	}
	return peak
}

// chartGutter is the room that the scale of a chart takes on the left of its plot.
func (s *scene) chartGutter(c *chart) float64 {
	return math.Max(math.Max(s.widthOf(c.format(c.peak()), fontSmall), s.widthOf(c.format(0), fontSmall))+8, c.minGutter)
}

// chartSlot returns the bucket index under a horizontal position in a plot, or -1.
func chartSlot(mouseX, plotX, plotWidth float64, count int) int {
	if count <= 0 || plotWidth <= 0 || mouseX < plotX || mouseX >= plotX+plotWidth {
		return -1
	}
	index := int((mouseX - plotX) / plotWidth * float64(count))
	if index >= count {
		index = count - 1
	}
	return index
}

// axisLabel says how long ago a point of the time axis is.
func axisLabel(ago time.Duration) string {
	return formatAgo(ago)
}

// timeAxis draws the labels of a time axis under a plot, with the first and last labels at the ends and those in
// between left out where a narrow plot has no room for them. text, if set, writes the label at a fraction of the
// width; otherwise each says how long ago its point is.
func (s *scene) timeAxis(plotX, plotWidth, y, height float64, span time.Duration, text func(fraction float64) string) {
	const axisLabels = 4
	var labelLeft, labelRight [axisLabels]float64
	var labels [axisLabels]string
	for i := range labels {
		if text != nil {
			labels[i] = text(float64(i) / (axisLabels - 1))
		} else {
			labels[i] = axisLabel(span * time.Duration(axisLabels-1-i) / (axisLabels - 1))
		}
		labelWidth := s.widthOf(labels[i], fontSmall)
		center := plotX + plotWidth*float64(i)/(axisLabels-1)
		labelLeft[i] = math.Min(math.Max(center-labelWidth/2, plotX), plotX+plotWidth-labelWidth)
		labelRight[i] = labelLeft[i] + labelWidth
	}
	drawnRight := math.Inf(-1)
	for i := range labels {
		if i > 0 && i < axisLabels-1 && (labelLeft[i] < drawnRight+8 || labelRight[i]+8 > labelLeft[axisLabels-1]) {
			continue
		}
		s.label(labels[i], fontSmall, theme.muted, labelLeft[i], y, labelRight[i]-labelLeft[i]+2, height, textLeft)
		drawnRight = labelRight[i]
	}
}

// polyline draws a line through any number of points, as runs of shapes that share their end points.
func (s *scene) polyline(width float64, color rgb, points [][2]float64) {
	const most = len(sceneShape{}.points)
	for start := 0; start+1 < len(points); start += most - 1 {
		end := min(start+most, len(points))
		flat := make([]float64, 0, 2*(end-start))
		for _, point := range points[start:end] {
			flat = append(flat, point[0], point[1])
		}
		s.line(width, color, flat...)
	}
}

// chart draws a graph and returns its height.
func (s *scene) chart(x, y, w float64, c *chart) float64 {
	const pad, captionHeight, axisHeight = 12, 18, 16
	height := c.height
	s.fill(x, y, w, height, 8, theme.panel)

	peak := c.peak()
	peakText, zeroText := c.format(peak), c.format(0)
	gutter := s.chartGutter(c)

	plotX, plotWidth := x+pad+gutter, w-2*pad-gutter
	plotTop, plotBottom := y+8+captionHeight+10, y+height-8-axisHeight-4
	count := len(c.buckets)
	slot := plotWidth / float64(max(count, 1))

	// Which bucket the mouse is over decides what the caption and the legend say.
	hovered := -1
	if s.hover(c.id, plotX, plotTop-6, plotWidth, plotBottom-plotTop+12) {
		hovered = chartSlot(s.mouseX, plotX, plotWidth, count)
	}
	caption := c.caption
	var legend []chartLegend
	if hovered >= 0 {
		if c.hoverCaption != nil {
			caption = c.hoverCaption(hovered)
		} else {
			caption = c.end.Add(-c.span + time.Duration(hovered)*c.span/time.Duration(count)).Format(c.timeFormat)
		}
		legend = c.legend(&c.buckets[hovered])
	} else {
		legend = c.legend(nil)
	}
	legendX := x + w - pad
	for i := len(legend) - 1; i >= 0; i-- {
		textWidth := s.widthOf(legend[i].text, fontSmall)
		legendX -= textWidth
		s.label(legend[i].text, fontSmall, theme.text, legendX, y+8, textWidth+2, captionHeight, textLeft)
		legendX -= 12
		s.fill(legendX, y+13, 8, 8, 4, legend[i].color)
		legendX -= 14
	}
	captionColor := theme.textDim
	if hovered >= 0 {
		captionColor = theme.text
	}
	s.label(caption, fontSmall, captionColor, x+pad, y+8, legendX-x-pad, captionHeight, textLeft)

	// The scale, with lines at the peak and at zero
	baseline := plotBottom
	if c.mirror {
		baseline = (plotTop + plotBottom) / 2
	}
	s.label(peakText, fontSmall, theme.muted, x+pad, plotTop-8, gutter-8, 16, textRight)
	s.label(zeroText, fontSmall, theme.muted, x+pad, baseline-8, gutter-8, 16, textRight)
	s.fill(plotX, plotTop-0.5, plotWidth, 1, 0, theme.line)
	if c.mirror {
		s.label(peakText, fontSmall, theme.muted, x+pad, plotBottom-8, gutter-8, 16, textRight)
		s.fill(plotX, plotBottom-0.5, plotWidth, 1, 0, theme.line)
	}
	s.fill(plotX, baseline-0.5, plotWidth, 1, 0, theme.border)

	s.timeAxis(plotX, plotWidth, plotBottom+6, axisHeight, c.span, c.axisText)

	// The series
	for series := range c.series {
		down := c.mirror && series == 1
		room := baseline - plotTop
		if down {
			room = plotBottom - baseline
		}
		valueY := func(value float64) float64 {
			offset := math.Min(value/peak, 1) * (room - 1)
			if down {
				return baseline + 0.5 + offset
			}
			return baseline - 0.5 - offset
		}
		color, fill := c.series[series].color, c.series[series].fill
		if c.bars {
			barWidth := slot - 1
			if barWidth < 1.5 {
				barWidth = slot
			}
			// The newest bar grows out of the baseline when it arrives. It is told apart by the time of its sample,
			// as its slot moves with the clock, and only once the chart was drawn before, so that opening a screen
			// does not make it grow.
			newest := -1
			for i := len(c.buckets) - 1; i >= 0; i-- {
				if c.buckets[i].has[series] {
					newest = i
					break
				}
			}
			grows := s.animationKnown(c.id + ":drawn")
			for i := range c.buckets {
				if !c.buckets[i].has[series] {
					continue
				}
				value := c.buckets[i].value[series]
				if i == newest && !c.buckets[i].at.IsZero() {
					id := c.id + ":bar:" + strconv.Itoa(series) + ":" + strconv.FormatInt(c.buckets[i].at.UnixNano(), 10)
					if grows {
						value *= s.animateFrom(id, 0, 1)
					} else {
						value *= s.animate(id, 1)
					}
				}
				top := valueY(value)
				if math.Abs(top-baseline) < 1 {
					continue
				}
				barX := plotX + float64(i)*slot
				if down {
					s.fill(barX, baseline+0.5, barWidth, top-baseline-0.5, 1, color)
				} else {
					s.fill(barX, top, barWidth, baseline-0.5-top, 1, color)
				}
			}
			continue
		}
		// A filled line, broken where there is no data. The area under it is drawn as one four-sided shape per
		// step, each reaching a little into the next so that no seam shows between them.
		var run [][2]float64
		flush := func() {
			switch len(run) {
			case 0:
				return
			case 1:
				left, right := run[0][0]-slot/2, run[0][0]+slot/2
				s.poly(fill, left, baseline, left, run[0][1], right, run[0][1], right, baseline)
				s.line(1.5, color, left, run[0][1], right, run[0][1])
			default:
				for i := 0; i+1 < len(run); i++ {
					x0, y0, x1, y1 := run[i][0], run[i][1], run[i+1][0], run[i+1][1]
					if i+2 < len(run) {
						const reach = 0.6
						y1 += (y1 - y0) / (x1 - x0) * reach
						x1 += reach
						if down {
							y1 = math.Max(y1, baseline)
						} else {
							y1 = math.Min(y1, baseline)
						}
					}
					s.poly(fill, x0, baseline, x0, y0, x1, y1, x1, baseline)
				}
				s.polyline(1.5, color, run)
			}
			run = run[:0]
		}
		for i := range c.buckets {
			if !c.buckets[i].has[series] {
				flush()
				continue
			}
			run = append(run, [2]float64{plotX + (float64(i)+0.5)*slot, valueY(c.buckets[i].value[series])})
		}
		flush()
	}

	s.animate(c.id+":drawn", 1)

	if c.lossMarks {
		markWidth := math.Max(slot-1, 2)
		for i := range c.buckets {
			bucket := &c.buckets[i]
			if bucket.lost <= 0 || bucket.sent <= 0 {
				continue
			}
			markHeight := 4 + 8*math.Min(float64(bucket.lost)/float64(bucket.sent), 1)
			s.fill(plotX+float64(i)*slot+(slot-markWidth)/2, baseline-markHeight, markWidth, markHeight, 1, theme.red)
		}
	}

	if hovered >= 0 {
		centerX := plotX + (float64(hovered)+0.5)*slot
		s.fill(centerX-0.5, plotTop, 1, plotBottom-plotTop, 0, theme.textDim)
		for series := range c.series {
			bucket := &c.buckets[hovered]
			if !bucket.has[series] {
				continue
			}
			down := c.mirror && series == 1
			room := baseline - plotTop
			if down {
				room = plotBottom - baseline
			}
			offset := math.Min(bucket.value[series]/peak, 1) * (room - 1)
			dotY := baseline - 0.5 - offset
			if down {
				dotY = baseline + 0.5 + offset
			}
			s.fill(centerX-4, dotY-4, 8, 8, 4, c.series[series].color)
			s.stroke(centerX-4, dotY-4, 8, 8, 4, 1.5, theme.panel)
		}
	}
	return height
}

// trafficChart is the graph of what a tunnel received, drawn upwards, and sent, drawn downwards.
func trafficChart(id string, samples tunnelSamples, r chartRange, end time.Time, height float64) *chart {
	current := currentRate(samples.seconds)
	return &chart{
		id:         id,
		caption:    l18n.Sprintf("Traffic"),
		height:     height,
		series:     []chartSeries{{theme.green, theme.greenFill}, {theme.blue, theme.blueFill}},
		mirror:     true,
		buckets:    trafficBuckets(samples, r, end),
		end:        end,
		span:       r.span(),
		timeFormat: r.timeFormat(),
		bars:       r == rangeMinute,
		minPeak:    1024,
		format:     formatRate,
		legend: func(bucket *chartBucket) []chartLegend {
			rx, tx := formatRate(current.rx), formatRate(current.tx)
			if bucket != nil {
				rx, tx = "–", "–"
				if bucket.has[0] {
					rx = formatRate(bucket.value[0])
				}
				if bucket.has[1] {
					tx = formatRate(bucket.value[1])
				}
			}
			return []chartLegend{{theme.green, l18n.Sprintf("In %s", rx)}, {theme.blue, l18n.Sprintf("Out %s", tx)}}
		},
	}
}

// latencyChart is the graph of the round trips of the probes, with the lost ones marked, or nil if the range
// holds no probes.
func latencyChart(id string, samples tunnelSamples, r chartRange, end time.Time, height float64) *chart {
	buckets := latencyBuckets(samples, r, end)
	if buckets == nil {
		return nil
	}
	quality := summarizeQuality(samples.seconds)
	return &chart{
		id:         id,
		caption:    l18n.Sprintf("Latency"),
		height:     height,
		series:     []chartSeries{{theme.violet, theme.violetFill}},
		buckets:    buckets,
		end:        end,
		span:       r.span(),
		timeFormat: r.timeFormat(),
		bars:       r == rangeMinute,
		lossMarks:  true,
		minPeak:    10,
		format: func(ms float64) string {
			return formatLatency(time.Duration(ms * float64(time.Millisecond)))
		},
		legend: func(bucket *chartBucket) []chartLegend {
			if bucket == nil {
				latency := "–"
				if quality.answered {
					latency = formatLatency(quality.latency)
				}
				lost := l18n.Sprintf("%s lost", formatPercent(quality.lossPercent()))
				if !quality.everAnswered {
					// Losing every probe to a target that never answered says nothing about the tunnel.
					lost = l18n.Sprintf("No reply")
				}
				return []chartLegend{{theme.violet, latency}, {theme.red, lost}}
			}
			latency, lost := "–", "–"
			if bucket.has[0] {
				latency = formatLatency(time.Duration(bucket.value[0] * float64(time.Millisecond)))
			}
			if bucket.sent > 0 {
				lost = l18n.Sprintf("%d of %d lost", bucket.lost, bucket.sent)
			}
			return []chartLegend{{theme.violet, latency}, {theme.red, lost}}
		},
	}
}

// rangeChips draws the choice of time range and returns their height.
func (s *scene) rangeChips(x, y float64, selected chartRange, choose func(chartRange)) float64 {
	for r := chartRange(0); r < chartRangeCount; r++ {
		r := r
		x += s.chip("range:"+strconv.Itoa(int(r)), x, y, r.label(), r == selected, theme.text, func() { choose(r) }) + 6
	}
	return 30
}
