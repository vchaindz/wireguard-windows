/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"
	"testing"
	"time"
)

// The expectations are written with ordinary spaces; the formatters put non-breaking ones between number and unit.
func plainSpaces(s string) string {
	return strings.ReplaceAll(s, " ", " ")
}

func TestFormatBytes(t *testing.T) {
	const k, m, g = 1024, 1024 * 1024, 1024 * 1024 * 1024
	for _, c := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1,023 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{10*k - 6, "9.99 KB"},
		{10*k - 2, "10.0 KB"}, // 9.998 KB rounds to ten, which takes one decimal fewer
		{100*k - 60, "99.9 KB"},
		{100*k - 20, "100 KB"},
		{999 * k, "999 KB"},
		{999*k + k/2 - 1, "999 KB"},
		{999*k + k/2, "0.98 MB"}, // 999.5 KB would round to 1000 KB, four digits
		{1023 * k, "1.00 MB"},
		{m, "1.00 MB"},
		{218 * m, "218 MB"},
		{1331439862, "1.24 GB"},
		{1023 * g, "1.00 TB"},
		{5000 * 1024 * g, "5,000 TB"}, // the largest unit has nowhere to go
	} {
		if got := plainSpaces(formatBytes(c.bytes)); got != c.want {
			t.Errorf("%d: got %q, want %q", c.bytes, got, c.want)
		}
	}
}

func TestFormatRate(t *testing.T) {
	for _, c := range []struct {
		rate float64
		want string
	}{
		{-3, "0 B/s"},
		{0, "0 B/s"},
		{0.4, "0 B/s"},
		{1023.4, "1,023 B/s"},
		{1023.6, "1.0 KB/s"},
		{1024, "1.0 KB/s"},
		{9.94 * 1024, "9.9 KB/s"},
		{9.96 * 1024, "10 KB/s"},
		{120 * 1024, "120 KB/s"},
		{999.4 * 1024, "999 KB/s"},
		{999.6 * 1024, "1.0 MB/s"},
		{1.2 * 1024 * 1024, "1.2 MB/s"},
		{56 * 1024 * 1024, "56 MB/s"},
	} {
		if got := plainSpaces(formatRate(c.rate)); got != c.want {
			t.Errorf("%v: got %q, want %q", c.rate, got, c.want)
		}
	}
}

func TestFormatAgo(t *testing.T) {
	for _, c := range []struct {
		ago  time.Duration
		want string
	}{
		{-time.Second, "now"},
		{999 * time.Millisecond, "now"},
		{time.Second, "1 s ago"},
		{43 * time.Second, "43 s ago"},
		{59*time.Second + 999*time.Millisecond, "59 s ago"},
		{time.Minute, "1 min ago"},
		{5*time.Minute + 59*time.Second, "5 min ago"},
		{59 * time.Minute, "59 min ago"},
		{time.Hour, "1 h ago"},
		{2*time.Hour + 50*time.Minute, "2 h ago"},
		{47 * time.Hour, "47 h ago"},
		{48 * time.Hour, "2 d ago"},
		{9*24*time.Hour + 23*time.Hour, "9 d ago"},
	} {
		if got := formatAgo(c.ago); got != c.want {
			t.Errorf("%v: got %q, want %q", c.ago, got, c.want)
		}
	}
}
