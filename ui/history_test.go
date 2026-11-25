/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/manager"
)

func TestFormatDay(t *testing.T) {
	now := time.Date(2026, 3, 11, 15, 0, 0, 0, time.Local)
	for _, c := range []struct {
		day  time.Time
		want string
	}{
		{time.Date(2026, 3, 11, 0, 0, 0, 0, time.Local), "Today"},
		{time.Date(2026, 3, 11, 23, 59, 0, 0, time.Local), "Today"},
		{time.Date(2026, 3, 10, 0, 0, 0, 0, time.Local), "Yesterday"},
		{time.Date(2026, 3, 9, 0, 0, 0, 0, time.Local), "Mon 9 Mar"},
		{time.Date(2026, 1, 1, 0, 0, 0, 0, time.Local), "Thu 1 Jan"},
		{time.Date(2025, 12, 31, 0, 0, 0, 0, time.Local), "Wed 31 Dec 2025"},
		// A day recorded in another time zone keeps its date.
		{time.Date(2026, 3, 10, 0, 0, 0, 0, time.FixedZone("", 14*3600)), "Yesterday"},
	} {
		if got := formatDay(c.day, now); got != c.want {
			t.Errorf("%v: got %q, want %q", c.day, got, c.want)
		}
	}
	// Yesterday across the turn of a year and of a month.
	if got := formatDay(time.Date(2025, 12, 31, 0, 0, 0, 0, time.Local), time.Date(2026, 1, 1, 8, 0, 0, 0, time.Local)); got != "Yesterday" {
		t.Errorf("new year: got %q", got)
	}
	if got := formatDay(time.Date(2026, 2, 28, 0, 0, 0, 0, time.Local), time.Date(2026, 3, 1, 8, 0, 0, 0, time.Local)); got != "Yesterday" {
		t.Errorf("new month: got %q", got)
	}
}

func TestFormatClock(t *testing.T) {
	now := time.Date(2026, 3, 11, 15, 0, 0, 0, time.Local)
	if got := formatClock(time.Date(2026, 3, 11, 9, 5, 59, 0, time.Local)); got != "09:05" {
		t.Errorf("morning: got %q", got)
	}
	if got := formatClock(time.Date(2026, 3, 11, 21, 40, 0, 0, time.Local)); got != "21:40" {
		t.Errorf("evening: got %q", got)
	}
	if got := formatDayAndClock(time.Date(2026, 3, 10, 21, 40, 0, 0, time.Local), now); got != "Yesterday 21:40" {
		t.Errorf("yesterday: got %q", got)
	}
	if got := formatDayAndClock(time.Date(2026, 3, 8, 7, 3, 0, 0, time.Local), now); got != "Sun 8 Mar 07:03" {
		t.Errorf("earlier: got %q", got)
	}
	// A time recorded in another zone is shown in the local one.
	utc := time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC)
	if got, want := formatDayAndClock(utc, now), "Today "+utc.Local().Format("15:04"); utc.Local().Day() == 11 && got != want {
		t.Errorf("other zone: got %q, want %q", got, want)
	}
}

func usageDay(year int, month time.Month, day int, rx, tx uint64, active, connected uint32) manager.TunnelDayUsage {
	return manager.TunnelDayUsage{Day: time.Date(year, month, day, 0, 0, 0, 0, time.Local), RxBytes: rx, TxBytes: tx, ActiveSeconds: active, ConnectedSeconds: connected}
}

func TestUsageOfLastDays(t *testing.T) {
	now := time.Date(2026, 3, 11, 15, 0, 0, 0, time.Local)
	days := []manager.TunnelDayUsage{
		usageDay(2026, 2, 9, 1, 1, 100, 100), // 31 days before: in no total
		usageDay(2026, 2, 10, 2, 2, 200, 100),
		usageDay(2026, 3, 4, 4, 4, 400, 400), // 8 days ago with today: not in the week
		usageDay(2026, 3, 5, 8, 8, 800, 800),
		usageDay(2026, 3, 11, 16, 32, 1600, 1500),
	}
	for _, c := range []struct {
		count  int
		rx, tx uint64
		active time.Duration
	}{
		{1, 16, 32, 1600 * time.Second},
		{7, 24, 40, 2400 * time.Second},
		{30, 30, 46, 3000 * time.Second},
	} {
		got := usageOfLastDays(days, now, c.count)
		if got.rx != c.rx || got.tx != c.tx || got.active != c.active {
			t.Errorf("last %d days: %+v", c.count, got)
		}
	}
	if percent, ok := uptimePercent(usageOfLastDays(days, now, 30)); ok {
		t.Errorf("uptime shown for 50 min of activity: %v", percent)
	}
	days = append(days[:4], usageDay(2026, 3, 11, 0, 0, 7200, 6840))
	if percent, ok := uptimePercent(usageOfLastDays(days, now, 30)); !ok || percent < 94.6 || percent > 94.7 { // 8140 of 8600 s
		t.Errorf("uptime %v, %v", percent, ok)
	}

	recent, recorded := lastDays(days, now, 30)
	if len(recent) != 30 || !recorded[29] || recent[29].ActiveSeconds != 7200 || recorded[28] || !recorded[0] || recent[0].RxBytes != 2 {
		t.Errorf("last days: first %+v, last %+v", recent[0], recent[29])
	}
}

func TestHistoryCSV(t *testing.T) {
	zone := time.FixedZone("", 3600)
	history := manager.TunnelHistory{
		Sessions: []manager.TunnelSession{
			{
				Start: time.Date(2026, 3, 10, 9, 0, 0, 0, zone), End: time.Date(2026, 3, 10, 11, 30, 5, 0, zone),
				ActiveSeconds: 9005, ConnectedSeconds: 8990, RxBytes: 1331439862, TxBytes: 228589568,
				ConnectionFailures: 1, Reconnects: 0, Endpoint: "vpn.example.com:51820", EndedBy: manager.SessionDeactivated,
			},
			{
				Start: time.Date(2026, 3, 11, 8, 0, 0, 0, zone), End: time.Date(2026, 3, 11, 8, 1, 0, 0, zone),
				ActiveSeconds: 60, ConnectedSeconds: 0, Endpoint: "[fe80::1%eth0]:51820", EndedBy: manager.SessionInProgress,
			},
		},
		Days: []manager.TunnelDayUsage{
			{Day: time.Date(2026, 3, 10, 0, 0, 0, 0, zone), RxBytes: 1331439862, TxBytes: 228589568, ActiveSeconds: 9005, ConnectedSeconds: 8990},
			{Day: time.Date(2026, 3, 11, 0, 0, 0, 0, zone), ActiveSeconds: 60},
		},
	}
	var out strings.Builder
	if err := writeHistoryCSV(&out, history); err != nil {
		t.Fatal(err)
	}
	want := "session_start,session_end,active_seconds,connected_seconds,received_bytes,sent_bytes,connection_failures,reconnects,endpoint,ended_by\r\n" +
		"2026-03-10T09:00:00+01:00,2026-03-10T11:30:05+01:00,9005,8990,1331439862,228589568,1,0,vpn.example.com:51820,deactivated\r\n" +
		"2026-03-11T08:00:00+01:00,2026-03-11T08:01:00+01:00,60,0,0,0,0,0,[fe80::1%eth0]:51820,in_progress\r\n" +
		"\r\n" +
		"day,received_bytes,sent_bytes,active_seconds,connected_seconds\r\n" +
		"2026-03-10,1331439862,228589568,9005,8990\r\n" +
		"2026-03-11,0,0,60,0\r\n"
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}

	out.Reset()
	writeHistoryCSV(&out, manager.TunnelHistory{})
	if out.String() != "session_start,session_end,active_seconds,connected_seconds,received_bytes,sent_bytes,connection_failures,reconnects,endpoint,ended_by\r\n\r\nday,received_bytes,sent_bytes,active_seconds,connected_seconds\r\n" {
		t.Errorf("empty: %q", out.String())
	}
}

// sampleHistory is a month of use of a tunnel: a session most days, one cut by sleep and one by the manager
// stopping, and the current one in progress.
func sampleHistory(now time.Time) manager.TunnelHistory {
	var history manager.TunnelHistory
	year, month, day := now.Date()
	endings := []manager.SessionEnd{manager.SessionDeactivated, manager.SessionDeactivated, manager.SessionSuspended, manager.SessionDeactivated, manager.SessionManagerStopped}
	for i := 29; i >= 0; i-- {
		if i%6 == 4 {
			continue
		}
		midnight := time.Date(year, month, day-i, 0, 0, 0, 0, time.Local)
		active := uint32(3600 + (i*1733)%14000)
		rx, tx := uint64(40+(i*37)%400)<<20, uint64(5+(i*13)%60)<<20
		start := midnight.Add(8*time.Hour + time.Duration(i%5)*17*time.Minute)
		dayActive := active
		if i == 0 {
			// The current session began three hours ago, which may have been yesterday.
			active, rx, tx = 3*3600+12*60, 182<<20, 21<<20
			start = now.Add(-time.Duration(active) * time.Second)
			dayActive = min(active, uint32(now.Sub(midnight)/time.Second))
		}
		history.Days = append(history.Days, manager.TunnelDayUsage{Day: midnight, RxBytes: rx, TxBytes: tx, ActiveSeconds: dayActive, ConnectedSeconds: dayActive - dayActive/25})
		session := manager.TunnelSession{
			Start: start, End: start.Add(time.Duration(active) * time.Second),
			ActiveSeconds: active, ConnectedSeconds: active - active/25, RxBytes: rx, TxBytes: tx,
			Endpoint: "vpn.example.com:51820", EndedBy: endings[i%len(endings)],
		}
		if i == 0 {
			session.EndedBy, session.End = manager.SessionInProgress, now
		}
		history.Sessions = append(history.Sessions, session)
	}
	return history
}

// TestRenderHistory draws the history on the details screen: usage and sessions, the full list of sessions, a
// tunnel with nothing recorded yet, history disabled by policy, the usage chart under the mouse, and what a limited
// operator sees.
func TestRenderHistory(t *testing.T) {
	inEachPalette(t, renderHistory)
}

func renderHistory(t *testing.T, suffix string) {
	wasAdmin := IsAdmin
	defer func() { IsAdmin = wasAdmin }()

	now := time.Now()
	office := tunnelEntry{tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStarted, health: manager.TunnelHealthConnected}
	office.config = sampleConfig("office", "10.8.0.2/24", 42*time.Second, 1331439862, 228589568)
	office.metrics = manager.TunnelMetrics{ActiveSince: now.Add(-3 * time.Hour), ConnectedSince: now.Add(-47 * time.Minute)}
	office.settings, office.probingAllowed, office.settingsLoaded = manager.TunnelSettings{Color: "blue"}, true, true
	office.history, office.historyEnabled, office.historyLoaded = sampleHistory(now), true, true
	backup := tunnelEntry{tunnel: manager.Tunnel{Name: "backup-site"}, state: manager.TunnelStopped}
	backup.config = sampleConfig("backup-site", "10.9.0.2/24", 0, 0, 0)
	backup.settingsLoaded = true
	samples := tunnelSamples{seconds: sampleSeries(now, 120, time.Second, nil)}

	window := func(details string, expanded bool, edit func(office, backup *tunnelEntry)) *ManageTunnelsWindow {
		o, b := office, backup
		if edit != nil {
			edit(&o, &b)
		}
		return &ManageTunnelsWindow{
			screen: screenDetails, detailsName: details, historyExpanded: expanded,
			model: &appModel{entries: []tunnelEntry{b, o}, globalState: manager.TunnelStarted, samples: map[string]tunnelSamples{"office": samples}},
		}
	}
	// scrollTo is how far the details screen must scroll for a text to be near its top.
	scrollTo := func(mtw *ManageTunnelsWindow, text string) float64 {
		s, _ := renderSceneWith(t, 524, 820, 1, 0, "", mtw.buildDetails)
		for i := range s.texts {
			if s.texts[i].text == text {
				return min(max(s.texts[i].rect.y-headerHeight-30, 0), s.maxScroll)
			}
		}
		t.Fatalf("no text %q to scroll to", text)
		return 0
	}

	for _, c := range []struct {
		name     string
		admin    bool
		mtw      *ManageTunnelsWindow
		scrollTo string
		want     []string
		absent   []string
		hits     []string
		noHits   []string
	}{
		{"history-details", true, window("office", false, nil), "USAGE",
			[]string{"USAGE", "Today", "Last 7 days", "Last 30 days", "Uptime", "Last 30 days", "SESSIONS", "in progress", "Show all 25 sessions", "Save history…", "Clear history"},
			nil, []string{"chart:usage", "history-more", "history-save", "history-clear"}, nil},
		{"history-sessions-expanded", true, window("office", true, nil), "SESSIONS",
			[]string{"Show fewer", "computer went to sleep", "WireGuard service stopped", "deactivated"},
			[]string{"Show all 25 sessions"}, []string{"history-more"}, nil},
		{"history-empty", true, window("backup-site", false, func(_, backup *tunnelEntry) {
			backup.historyEnabled, backup.historyLoaded = true, true
		}), "HISTORY", []string{"Nothing recorded yet"}, []string{"USAGE", "SESSIONS"}, nil, []string{"history-save", "history-clear", "chart:usage"}},
		{"history-disabled", true, window("backup-site", false, func(_, backup *tunnelEntry) {
			backup.history, backup.historyEnabled, backup.historyLoaded = sampleHistory(now), false, true
		}), "Connection history is disabled by policy.", []string{"Connection history is disabled by policy."}, []string{"USAGE", "SESSIONS"}, nil, []string{"history-save", "history-clear"}},
		{"history-operator", false, window("office", false, nil), "Save history…",
			[]string{"Save history…"}, []string{"Clear history"}, []string{"history-save"}, []string{"history-clear"}},
		{"history-actions", true, window("office", false, nil), "Save history…",
			[]string{"Show all 25 sessions", "Save history…", "Clear history"}, nil, []string{"history-more", "history-save", "history-clear"}, nil},
	} {
		IsAdmin = c.admin
		scroll := scrollTo(c.mtw, c.scrollTo)
		s, img := renderSceneWith(t, 524, 820, 1, scroll, "", c.mtw.buildDetails)
		texts := make(map[string]bool)
		for i := range s.texts {
			texts[s.texts[i].text] = true
		}
		contains := func(want string) bool {
			for text := range texts {
				if strings.Contains(text, want) {
					return true
				}
			}
			return false
		}
		for _, want := range c.want {
			if !contains(want) {
				t.Errorf("%s: no text with %q", c.name, want)
			}
		}
		for _, absent := range c.absent {
			if contains(absent) {
				t.Errorf("%s: text with %q", c.name, absent)
			}
		}
		for _, id := range c.hits {
			if hit := s.hitByID(id); hit == nil || hit.action == nil && id != "chart:usage" {
				t.Errorf("%s: no region %q", c.name, id)
			}
		}
		for _, id := range c.noHits {
			if s.hitByID(id) != nil {
				t.Errorf("%s: region %q", c.name, id)
			}
		}
		seen := make(map[string]bool)
		for _, hit := range s.hits {
			if hit.action != nil && seen[hit.id] && !strings.HasPrefix(hit.id, "copy:") {
				t.Errorf("%s: region %q twice", c.name, hit.id)
			}
			seen[hit.id] = true
		}
		writePNG(t, c.name+suffix, img)
	}

	// The full list has a row for every session, the short one for the most recent ones.
	IsAdmin = true
	count := func(mtw *ManageTunnelsWindow) int {
		s, _ := renderSceneWith(t, 524, 820, 1, 0, "", mtw.buildDetails)
		rows := 0
		for i := range s.texts {
			if strings.HasPrefix(s.texts[i].text, "In ") && strings.Contains(s.texts[i].text, " · Out ") {
				rows++
			}
		}
		return rows
	}
	if short, all := count(window("office", false, nil)), count(window("office", true, nil)); short != sessionsShown || all != 25 {
		t.Errorf("sessions listed: %d short, %d in full", short, all)
	}
	// Showing all is operated like any other region, and the newest session comes first.
	mtw := window("office", false, nil)
	s, _ := renderSceneWith(t, 524, 820, 1, 0, "", mtw.buildDetails)
	s.hitByID("history-more").action()
	if !mtw.historyExpanded {
		t.Error("show all did not expand the list")
	}
	for i := range s.texts {
		if strings.HasSuffix(s.texts[i].text, "in progress") {
			for j := range s.texts {
				if strings.Contains(s.texts[j].text, "computer went to sleep") && s.texts[j].rect.y < s.texts[i].rect.y {
					t.Error("an older session is listed before the current one")
				}
			}
		}
	}

	// The usage chart under the mouse names the day and its traffic.
	mtw = window("office", false, nil)
	scroll := scrollTo(mtw, "USAGE")
	s, _ = renderSceneWith(t, 524, 820, 1, scroll, "", mtw.buildDetails)
	hit := s.hitByID("chart:usage")
	if hit == nil || !hit.tracksMouse || hit.action != nil {
		t.Fatal("the usage chart does not follow the mouse")
	}
	mouse := [2]float64{hit.rect.x + hit.rect.w - 4, hit.rect.y + hit.rect.h/2}
	hovered, img := renderSceneMouse(t, 524, 820, 1, scroll, "", &mouse, mtw.buildDetails)
	found := false
	for i := range hovered.texts {
		if strings.HasPrefix(hovered.texts[i].text, "Today · active ") {
			found = true
		}
	}
	if !found {
		t.Error("the bar of today does not say what it is under the mouse")
	}
	writePNG(t, "history-hover"+suffix, img)
}
