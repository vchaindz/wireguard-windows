/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
)

// Numbers as the custom-drawn screens show them. conf.Bytes and conf.HandshakeTime keep their own, more exact
// spelling, because the wg tool and the configuration view use it.

// byteUnit is a power of 1024 and how it is written after a number. Windows labels these KB, MB and GB, not
// KiB, MiB and GiB, so the screens do too.
type byteUnit int

const (
	unitKB byteUnit = iota
	unitMB
	unitGB
	unitTB
)

func (unit byteUnit) label(number string) string {
	switch unit {
	case unitKB:
		return l18n.Sprintf("%s KB", number)
	case unitMB:
		return l18n.Sprintf("%s MB", number)
	case unitGB:
		return l18n.Sprintf("%s GB", number)
	}
	return l18n.Sprintf("%s TB", number)
}

// scaleBytes divides a count of bytes by powers of 1024 until it reads well, and returns it with its number of
// decimals. digits is how many significant digits the number may show at most. A unit is left as soon as the
// rounded number would need more digits than that, so that 1023.7 KB becomes 1.00 MB rather than 1024 KB.
func scaleBytes(bytes float64, digits int) (value float64, decimals int, unit byteUnit) {
	value, unit = bytes/1024, unitKB
	for {
		decimals = decimalsFor(value, digits)
		if unit == unitTB || roundTo(value, decimals) < 1000 {
			return
		}
		value /= 1024
		unit++
	}
}

// decimalsFor is how many decimals keep a number at the given count of significant digits, never less than none.
// It looks at the number as it will be rounded, so that 9.996 counts as 10.0 and gets one decimal fewer.
func decimalsFor(value float64, digits int) int {
	decimals := digits - 1
	for limit := 10.0; decimals > 0 && roundTo(value, decimals) >= limit; limit *= 10 {
		decimals--
	}
	return decimals
}

func roundTo(value float64, decimals int) float64 {
	scale := 1.0
	for range decimals {
		scale *= 10
	}
	return float64(int64(value*scale+0.5)) / scale
}

// formatNumber writes a number with a fixed count of decimals in the user's language.
func formatNumber(value float64, decimals int) string {
	switch decimals {
	case 0:
		return l18n.Sprintf("%.0f", roundTo(value, 0))
	case 1:
		return l18n.Sprintf("%.1f", roundTo(value, 1))
	}
	return l18n.Sprintf("%.2f", roundTo(value, 2))
}

// formatBytes writes an amount of data with three significant digits at most, as in "218 MB" or "1.24 GB".
// Amounts below a kilobyte are written exactly.
func formatBytes(bytes uint64) string {
	if bytes < 1024 {
		return l18n.Sprintf("%d B", bytes)
	}
	value, decimals, unit := scaleBytes(float64(bytes), 3)
	return unit.label(formatNumber(value, decimals))
}

// formatRate writes a rate of data with two significant digits at most, as in "1.2 MB/s", since the rate changes
// every second and more digits would only flicker.
func formatRate(bytesPerSecond float64) string {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	if bytesPerSecond+0.5 < 1024 {
		return l18n.Sprintf("%d B/s", int(bytesPerSecond+0.5))
	}
	value, decimals, unit := scaleBytes(bytesPerSecond, 2)
	return l18n.Sprintf("%s/s", unit.label(formatNumber(value, decimals)))
}

// formatAgo says how long ago something happened in the one unit that matters, as in "43 s ago" or "5 min ago".
// Each unit is counted in whole steps, so that something is "1 min ago" only once a full minute has passed.
func formatAgo(ago time.Duration) string {
	switch {
	case ago < time.Second:
		return l18n.Sprintf("now")
	case ago < time.Minute:
		return l18n.Sprintf("%d s ago", int(ago/time.Second))
	case ago < time.Hour:
		return l18n.Sprintf("%d min ago", int(ago/time.Minute))
	case ago < 48*time.Hour:
		return l18n.Sprintf("%d h ago", int(ago/time.Hour))
	}
	return l18n.Sprintf("%d d ago", int(ago/(24*time.Hour)))
}

// Dates and times as the history shows them. The clock is always 24-hour, as it is in the log.

func weekdayName(day time.Weekday) string {
	switch day {
	case time.Monday:
		return l18n.Sprintf("Mon")
	case time.Tuesday:
		return l18n.Sprintf("Tue")
	case time.Wednesday:
		return l18n.Sprintf("Wed")
	case time.Thursday:
		return l18n.Sprintf("Thu")
	case time.Friday:
		return l18n.Sprintf("Fri")
	case time.Saturday:
		return l18n.Sprintf("Sat")
	}
	return l18n.Sprintf("Sun")
}

func monthName(month time.Month) string {
	switch month {
	case time.January:
		return l18n.Sprintf("Jan")
	case time.February:
		return l18n.Sprintf("Feb")
	case time.March:
		return l18n.Sprintf("Mar")
	case time.April:
		return l18n.Sprintf("Apr")
	case time.May:
		return l18n.Sprintf("May")
	case time.June:
		return l18n.Sprintf("Jun")
	case time.July:
		return l18n.Sprintf("Jul")
	case time.August:
		return l18n.Sprintf("Aug")
	case time.September:
		return l18n.Sprintf("Sep")
	case time.October:
		return l18n.Sprintf("Oct")
	case time.November:
		return l18n.Sprintf("Nov")
	}
	return l18n.Sprintf("Dec")
}

// formatDay names a calendar day as "Today", "Yesterday" or "Tue 10 Mar", with the year added for a day of another
// year than now. The day is taken as written in day's own time zone, so that a day recorded in another zone keeps
// its date. The numbers are passed as text, so that the year gets no thousands separator.
func formatDay(day, now time.Time) string {
	year, month, date := day.Date()
	nowYear, nowMonth, nowDate := now.Date()
	today := time.Date(nowYear, nowMonth, nowDate, 0, 0, 0, 0, time.UTC)
	switch time.Date(year, month, date, 0, 0, 0, 0, time.UTC) {
	case today:
		return l18n.Sprintf("Today")
	case today.AddDate(0, 0, -1):
		return l18n.Sprintf("Yesterday")
	}
	weekday := time.Date(year, month, date, 12, 0, 0, 0, time.UTC).Weekday()
	if year != nowYear {
		return l18n.Sprintf("%[1]s %[2]s %[3]s %[4]s", weekdayName(weekday), strconv.Itoa(date), monthName(month), strconv.Itoa(year))
	}
	return l18n.Sprintf("%[1]s %[2]s %[3]s", weekdayName(weekday), strconv.Itoa(date), monthName(month))
}

// formatClock writes the time of day as hours and minutes, as in "09:05".
func formatClock(t time.Time) string {
	return t.Format("15:04")
}

// formatDayAndClock writes a moment as its day and time, as in "Yesterday 21:40", in the time zone of now.
func formatDayAndClock(t, now time.Time) string {
	t = t.In(now.Location())
	return l18n.Sprintf("%[1]s %[2]s", formatDay(t, now), formatClock(t))
}

// handshakeAge is how long ago a handshake happened.
func handshakeAge(handshake conf.HandshakeTime, now time.Time) time.Duration {
	return now.Sub(time.Unix(0, int64(handshake)))
}
