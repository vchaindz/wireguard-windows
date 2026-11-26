/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
)

// historyClock drives a recorder with a wall clock and a monotonic clock that can be moved apart, as when the
// user changes the time of the computer.
type historyClock struct {
	wall time.Time
	mono time.Duration
}

func (c *historyClock) step(d time.Duration) {
	c.wall = c.wall.Add(d)
	c.mono += d
}

func newHistoryClock(wall string) *historyClock {
	t, err := time.Parse(time.RFC3339, wall)
	if err != nil {
		panic(err)
	}
	return &historyClock{wall: t, mono: time.Hour}
}

func (c *historyClock) observe(r *historyRecorder, rx, tx uint64, health TunnelHealth) bool {
	return r.observe(c.wall, c.mono, rx, tx, health, "vpn.example.com:51820")
}

func TestHistorySession(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T10:00:00Z")
	start := clock.wall

	// The first sample only sets where the counters start: the traffic before it is not this session's.
	if clock.observe(&r, 5000, 7000, TunnelHealthUnverified) {
		t.Fatal("first sample asks to be written")
	}
	// The peer does not answer at first: one failure, however long it lasts, and no connected time.
	for i := 0; i < 4; i++ {
		clock.step(5 * time.Second)
		clock.observe(&r, 5000, 7148, TunnelHealthWaitingForPeer)
	}
	// Connected for 30 s, then lost for 10 s, then connected again.
	rx, tx := uint64(5000), uint64(7148)
	for i := 0; i < 6; i++ {
		clock.step(5 * time.Second)
		rx, tx = rx+1000, tx+500
		clock.observe(&r, rx, tx, TunnelHealthConnected)
	}
	clock.step(5 * time.Second)
	clock.observe(&r, rx, tx, TunnelHealthNoConnection)
	clock.step(5 * time.Second)
	clock.observe(&r, rx, tx, TunnelHealthConnected)
	clock.step(3 * time.Second)
	if !r.stop(clock.wall, clock.mono) {
		t.Fatal("stop of an active session did nothing")
	}
	if r.stop(clock.wall, clock.mono) {
		t.Fatal("second stop did something")
	}

	if len(r.history.Sessions) != 1 || r.open != nil {
		t.Fatalf("got %d sessions, open %v", len(r.history.Sessions), r.open)
	}
	s := r.history.Sessions[0]
	// 4*5 waiting + 6*5 connected + 5 lost + 5 + 3 = 63 s active. Connected: the first connected interval is not
	// (the state before it was waiting), the next five are, the one ending in the loss is, the one after it is not,
	// and the 3 s after reconnecting are.
	if s.ActiveSeconds != 63 || s.ConnectedSeconds != 33 {
		t.Errorf("active %d s, connected %d s", s.ActiveSeconds, s.ConnectedSeconds)
	}
	if s.RxBytes != 6000 || s.TxBytes != 148+3000 || s.ConnectionFailures != 2 || s.Reconnects != 1 {
		t.Errorf("session %+v", s)
	}
	if !s.Start.Equal(start) || !s.End.Equal(clock.wall) || s.EndedBy != SessionDeactivated || s.Endpoint != "vpn.example.com:51820" {
		t.Errorf("session %v to %v, ended by %d, endpoint %q", s.Start, s.End, s.EndedBy, s.Endpoint)
	}
	if len(r.history.Days) != 1 || r.history.Days[0].ActiveSeconds != 63 || r.history.Days[0].ConnectedSeconds != 33 || r.history.Days[0].RxBytes != 6000 {
		t.Errorf("days %+v", r.history.Days)
	}
	if !r.history.Days[0].Day.Equal(time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("day %v", r.history.Days[0].Day)
	}
}

func TestHistoryMidnight(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T23:59:50Z")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	// 20 s across midnight with 2000 bytes received: 10 s and 1000 bytes on each day.
	clock.step(20 * time.Second)
	clock.observe(&r, 2000, 400, TunnelHealthConnected)
	clock.step(5 * time.Second)
	r.stop(clock.wall, clock.mono)

	days := r.history.Days
	if len(days) != 2 {
		t.Fatalf("days %+v", days)
	}
	if days[0].ActiveSeconds != 10 || days[0].ConnectedSeconds != 10 || days[0].RxBytes != 1000 || days[0].TxBytes != 200 {
		t.Errorf("first day %+v", days[0])
	}
	if days[1].ActiveSeconds != 15 || days[1].ConnectedSeconds != 15 || days[1].RxBytes != 1000 || days[1].TxBytes != 200 {
		t.Errorf("second day %+v", days[1])
	}
	if dayKey(days[1].Day) != 20260311 {
		t.Errorf("second day is %v", days[1].Day)
	}
	// The session is one, and has all of it.
	if s := r.history.Sessions[0]; s.ActiveSeconds != 25 || s.RxBytes != 2000 {
		t.Errorf("session %+v", s)
	}
}

func TestHistoryMidnightLocal(t *testing.T) {
	// Days are local days: in a zone ahead of UTC, midnight comes earlier.
	zone := time.FixedZone("UTC+2", 2*3600)
	var r historyRecorder
	r.observe(time.Date(2026, 3, 10, 23, 59, 55, 0, zone), time.Hour, 0, 0, TunnelHealthConnected, "")
	r.observe(time.Date(2026, 3, 11, 0, 0, 5, 0, zone), time.Hour+10*time.Second, 0, 0, TunnelHealthConnected, "")
	if len(r.history.Days) != 2 || r.history.Days[0].Day.Day() != 10 || r.history.Days[1].Day.Day() != 11 || r.history.Days[1].Day.Hour() != 0 {
		t.Fatalf("days %+v", r.history.Days)
	}
}

func TestHistorySuspend(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T22:00:00Z")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	for i := 0; i < 12; i++ {
		clock.step(5 * time.Second)
		clock.observe(&r, uint64(i+1)*100, 0, TunnelHealthConnected)
	}
	beforeSleep := clock.wall

	// A night of sleep: the monotonic clock runs on, and the next sample comes nine hours later.
	clock.step(9 * time.Hour)
	if !clock.observe(&r, 1300, 0, TunnelHealthUnverified) {
		t.Error("a suspension does not ask to write the closed session")
	}
	if len(r.history.Sessions) != 1 {
		t.Fatalf("sessions %+v", r.history.Sessions)
	}
	slept := r.history.Sessions[0]
	if slept.EndedBy != SessionSuspended || !slept.End.Equal(beforeSleep) || slept.ActiveSeconds != 60 || slept.ConnectedSeconds != 60 || slept.RxBytes != 1200 {
		t.Errorf("session before the sleep %+v", slept)
	}
	// The new session starts on waking, with the traffic of the gap but none of its time.
	if r.open == nil || !r.open.Start.Equal(clock.wall) || r.open.ActiveSeconds != 0 || r.open.RxBytes != 100 {
		t.Fatalf("session after the sleep %+v", r.open)
	}
	// After waking, a handshake is a first connection of the new session, not a reconnect.
	clock.step(5 * time.Second)
	clock.observe(&r, 1300, 0, TunnelHealthConnected)
	if r.open.Reconnects != 0 || r.open.ActiveSeconds != 5 {
		t.Errorf("after waking %+v", r.open)
	}
	// The sleep counts on no day.
	var active uint32
	for _, day := range r.history.Days {
		active += day.ActiveSeconds
	}
	if active != 65 {
		t.Errorf("active seconds on all days: %d", active)
	}

	// A tunnel stopped after a gap is closed at its last sample, as suspended.
	clock.step(40 * time.Second)
	r.stop(clock.wall, clock.mono)
	if last := r.history.Sessions[len(r.history.Sessions)-1]; last.EndedBy != SessionSuspended || last.ActiveSeconds != 5 {
		t.Errorf("stopped after a gap: %+v", last)
	}

	// A session that a gap cuts short before anything happened in it is not recorded.
	var empty historyRecorder
	clock.observe(&empty, 0, 0, TunnelHealthUnverified)
	clock.step(time.Minute)
	clock.observe(&empty, 0, 0, TunnelHealthUnverified)
	if len(empty.history.Sessions) != 0 {
		t.Errorf("empty session recorded: %+v", empty.history.Sessions)
	}
}

func TestHistoryClockChange(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00Z")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	clock.step(5 * time.Second)
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	// The clock is set back an hour between two samples five seconds apart, and later forward by two hours.
	clock.wall = clock.wall.Add(-time.Hour)
	clock.step(5 * time.Second)
	if clock.observe(&r, 0, 0, TunnelHealthConnected) {
		t.Error("a clock set back is taken for a suspension")
	}
	clock.wall = clock.wall.Add(2 * time.Hour)
	clock.step(5 * time.Second)
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	r.stop(clock.wall, clock.mono)
	if len(r.history.Sessions) != 1 {
		t.Fatalf("sessions %+v", r.history.Sessions)
	}
	// Durations follow the monotonic clock, whatever the wall clock did.
	if s := r.history.Sessions[0]; s.ActiveSeconds != 15 || s.ConnectedSeconds != 15 || s.EndedBy != SessionDeactivated {
		t.Errorf("session %+v", s)
	}
	var active uint32
	for _, day := range r.history.Days {
		active += day.ActiveSeconds
	}
	if active != 15 {
		t.Errorf("active seconds on all days: %d", active)
	}

	// A clock set back across midnight puts the time on the earlier day, which is kept in order.
	var back historyRecorder
	clock = newHistoryClock("2026-03-11T00:00:30Z")
	clock.observe(&back, 0, 0, TunnelHealthConnected)
	clock.step(5 * time.Second)
	clock.observe(&back, 0, 0, TunnelHealthConnected)
	clock.wall = clock.wall.Add(-2 * time.Hour)
	clock.step(5 * time.Second)
	clock.observe(&back, 0, 0, TunnelHealthConnected)
	if len(back.history.Days) != 2 || dayKey(back.history.Days[0].Day) != 20260310 || back.history.Days[0].ActiveSeconds != 5 || back.history.Days[1].ActiveSeconds != 5 {
		t.Errorf("days %+v", back.history.Days)
	}
}

func TestHistoryCounterReset(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00Z")
	clock.observe(&r, 1000, 1000, TunnelHealthConnected)
	clock.step(time.Second)
	clock.observe(&r, 1500, 1200, TunnelHealthConnected)
	// A peer was removed and added again: its counters start from zero.
	clock.step(time.Second)
	clock.observe(&r, 300, 1250, TunnelHealthConnected)
	if r.open.RxBytes != 800 || r.open.TxBytes != 250 {
		t.Errorf("after a reset: %+v", r.open)
	}
}

func TestHistorySubSecondIntervals(t *testing.T) {
	// Samples a little more or less than a second apart add up to the right total.
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00Z")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	for i := 0; i < 100; i++ {
		clock.step(time.Second + time.Duration(i%3-1)*7*time.Millisecond)
		clock.observe(&r, 0, 0, TunnelHealthConnected)
	}
	if r.open.ActiveSeconds != 99 && r.open.ActiveSeconds != 100 || r.history.Days[0].ActiveSeconds != r.open.ActiveSeconds {
		t.Errorf("session %d s, day %d s", r.open.ActiveSeconds, r.history.Days[0].ActiveSeconds)
	}
}

func TestHistorySaveInterval(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00Z")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	saves := 0
	for i := 0; i < 180; i++ {
		clock.step(time.Second)
		if clock.observe(&r, 0, 0, TunnelHealthConnected) {
			saves++
			if i+1 != 60*saves {
				t.Errorf("written after %d s", i+1)
			}
		}
	}
	if saves != 3 {
		t.Errorf("written %d times in three minutes", saves)
	}
}

func TestHistoryCaps(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2025-01-01T12:00:00Z")
	for i := 0; i < maxHistoryDays+20; i++ {
		clock.observe(&r, 0, 0, TunnelHealthConnected)
		clock.step(5 * time.Second)
		r.stop(clock.wall, clock.mono)
		clock.step(24 * time.Hour)
	}
	if len(r.history.Days) != maxHistoryDays || dayKey(r.history.Days[0].Day) != 20250121 {
		t.Errorf("%d days, first %v", len(r.history.Days), r.history.Days[0].Day)
	}
	// A day older than all of a full list is not kept.
	r.observe(time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC), clock.mono, 0, 0, TunnelHealthConnected, "")
	r.observe(time.Date(2024, 6, 1, 12, 0, 5, 0, time.UTC), clock.mono+5*time.Second, 0, 0, TunnelHealthConnected, "")
	if len(r.history.Days) != maxHistoryDays || dayKey(r.history.Days[0].Day) != 20250121 {
		t.Errorf("old day kept: first %v", r.history.Days[0].Day)
	}
	r.abandon()
	for i := 0; i < maxHistorySessions; i++ {
		clock.observe(&r, 0, 0, TunnelHealthConnected)
		clock.step(time.Second)
		r.stop(clock.wall, clock.mono)
	}
	if len(r.history.Sessions) != maxHistorySessions || !r.history.Sessions[maxHistorySessions-1].End.Equal(clock.wall) {
		t.Errorf("%d sessions", len(r.history.Sessions))
	}
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	if snapshot := r.snapshot(); len(snapshot.Sessions) != maxHistorySessions || snapshot.Sessions[maxHistorySessions-1].EndedBy != SessionInProgress {
		t.Errorf("snapshot with the open session: %d sessions", len(snapshot.Sessions))
	}
}

func TestHistoryClear(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00Z")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	clock.step(5 * time.Second)
	clock.observe(&r, 100, 100, TunnelHealthConnected)
	clock.step(5 * time.Second)
	r.stop(clock.wall, clock.mono)
	clock.step(time.Minute)
	clock.observe(&r, 100, 100, TunnelHealthConnected)
	clock.step(5 * time.Second)
	clock.observe(&r, 300, 100, TunnelHealthConnected)
	r.clear()
	if len(r.history.Sessions) != 0 || len(r.history.Days) != 0 || r.open == nil || r.open.RxBytes != 0 || r.open.ActiveSeconds != 0 {
		t.Fatalf("after clearing: %+v, open %+v", r.history, r.open)
	}
	// What follows is recorded from the clearing on.
	clock.step(5 * time.Second)
	clock.observe(&r, 350, 100, TunnelHealthConnected)
	if r.open.RxBytes != 50 || r.open.ActiveSeconds != 5 || !r.open.Start.Equal(clock.wall.Add(-5*time.Second)) {
		t.Errorf("after clearing: %+v", r.open)
	}
}

func TestRecordedEndpoint(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"vpn.example.com:51820", "vpn.example.com:51820"},
		{"[fe80::1%eth0]:51820", "[fe80::1%eth0]:51820"},
		{"a\"b\\c\x00d <e>", "abcde"},
		{strings.Repeat("x", 300), strings.Repeat("x", maxEndpointLength)},
	} {
		if got := recordedEndpoint(c.in); got != c.want {
			t.Errorf("%q: got %q", c.in, got)
		}
	}
}

func TestHistoryFile(t *testing.T) {
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00+01:00")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	clock.step(5 * time.Second)
	clock.observe(&r, 10, 20, TunnelHealthConnected)
	clock.step(5 * time.Second)
	r.stop(clock.wall, clock.mono)
	clock.step(time.Minute)
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	clock.step(5 * time.Second)
	clock.observe(&r, 30, 40, TunnelHealthConnected)

	contents, err := marshalTunnelHistory(r.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	history, err := parseTunnelHistory(contents)
	if err != nil {
		t.Fatal(err)
	}
	// The session that was in progress when the file was written is closed as ended by the manager, at the time
	// it was written.
	if len(history.Sessions) != 2 || history.Sessions[1].EndedBy != SessionManagerStopped || !history.Sessions[1].End.Equal(clock.wall) || history.Sessions[1].RxBytes != 30 {
		t.Fatalf("sessions %+v", history.Sessions)
	}
	if history.Sessions[0].EndedBy != SessionDeactivated || history.Sessions[0].ActiveSeconds != 10 {
		t.Errorf("first session %+v", history.Sessions[0])
	}
	if len(history.Days) != 1 || history.Days[0].RxBytes != 40 || history.Days[0].ActiveSeconds != 15 {
		t.Errorf("days %+v", history.Days)
	}
	// The local day survives the round trip with its offset.
	if _, offset := history.Days[0].Day.Zone(); offset != 3600 || history.Days[0].Day.Hour() != 0 {
		t.Errorf("day %v", history.Days[0].Day)
	}

	for name, bad := range map[string]string{
		"truncated":       string(contents[:len(contents)/2]),
		"empty":           "",
		"unknown version": strings.Replace(string(contents), `"Version":1`, `"Version":2`, 1),
		"no version":      strings.Replace(string(contents), `"Version":1,`, ``, 1),
		"bad end":         strings.Replace(string(contents), `"EndedBy":2`, `"EndedBy":9`, 1),
		"bad endpoint":    strings.Replace(string(contents), `vpn.example.com`, `vpn example`, 1),
		"days unordered":  `{"Version":1,"Sessions":[],"Days":[{"Day":"2026-03-11T00:00:00Z"},{"Day":"2026-03-10T00:00:00Z"}]}`,
		"zero day":        `{"Version":1,"Sessions":[],"Days":[{"RxBytes":1}]}`,
		"not an object":   `[1,2,3]`,
	} {
		if _, err := parseTunnelHistory([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tooMany := `{"Version":1,"Sessions":[` + strings.Repeat(`{"Start":"2026-03-10T12:00:00Z","End":"2026-03-10T12:00:00Z","EndedBy":2},`, maxHistorySessions) + `{"Start":"2026-03-10T12:00:00Z","End":"2026-03-10T12:00:00Z","EndedBy":2}]}`
	if _, err := parseTunnelHistory([]byte(tooMany)); err == nil {
		t.Error("too many sessions accepted")
	}
}

// TestHistoryWorstCaseSize fills every field of a full history with its largest value, in a time zone whose
// offset takes the most room, and checks that the file stays below the cap that reading it enforces.
func TestHistoryWorstCaseSize(t *testing.T) {
	zone := time.FixedZone("", -(11*3600 + 59*60))
	when := time.Date(2026, 12, 31, 23, 59, 59, 0, zone)
	var history TunnelHistory
	for i := 0; i < maxHistorySessions; i++ {
		history.Sessions = append(history.Sessions, TunnelSession{
			Start: when, End: when,
			ActiveSeconds: ^uint32(0), ConnectedSeconds: ^uint32(0),
			RxBytes: ^uint64(0), TxBytes: ^uint64(0),
			ConnectionFailures: ^uint32(0), Reconnects: ^uint32(0),
			Endpoint: strings.Repeat("x", maxEndpointLength),
			EndedBy:  SessionSuspended,
		})
	}
	for i := 0; i < maxHistoryDays; i++ {
		history.Days = append(history.Days, TunnelDayUsage{
			Day:     time.Date(2025, 1, 1+i, 0, 0, 0, 0, zone),
			RxBytes: ^uint64(0), TxBytes: ^uint64(0),
			ActiveSeconds: ^uint32(0), ConnectedSeconds: ^uint32(0),
		})
	}
	contents, err := marshalTunnelHistory(history)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("worst case: %d bytes of %d", len(contents), conf.MaxTunnelHistorySize)
	if _, err := parseTunnelHistory(contents); err != nil {
		t.Fatal(err)
	}
}

// historyTestRoot points the configuration store at one temporary directory for the whole test binary, as the
// store remembers its directories once found.
var (
	historyTestRootOnce sync.Once
	historyTestRootDir  string
)

func historyTestRoot(t *testing.T) string {
	historyTestRootOnce.Do(func() {
		dir, err := os.MkdirTemp("", "wireguard-manager-test")
		if err != nil {
			t.Fatal(err)
		}
		historyTestRootDir = dir
		conf.PresetRootDirectory(dir)
		os.MkdirAll(filepath.Join(dir, "Configurations"), 0o700)
		os.MkdirAll(filepath.Join(dir, "History"), 0o700)
	})
	return historyTestRootDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if historyTestRootDir != "" {
		os.RemoveAll(historyTestRootDir)
	}
	os.Exit(code)
}

// TestLoadTunnelHistories is what happens when the manager starts: a session that a crashed manager left open is
// closed at the time it was written, when the tunnel was last active is known again, and the history of a tunnel
// that no longer exists is removed.
func TestLoadTunnelHistories(t *testing.T) {
	if !historyAllowed() {
		t.Skip("connection history is disabled by policy on this computer")
	}
	root := historyTestRoot(t)
	const name, gone = "history-load-test", "history-gone-test"
	if err := os.WriteFile(filepath.Join(root, "Configurations", name+".conf.dpapi"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var r historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00Z")
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	clock.step(5 * time.Second)
	r.stop(clock.wall, clock.mono)
	clock.step(time.Hour)
	clock.observe(&r, 0, 0, TunnelHealthConnected)
	for i := 0; i < 18; i++ {
		clock.step(5 * time.Second)
		clock.observe(&r, 0, 0, TunnelHealthConnected)
	}
	contents, err := marshalTunnelHistory(r.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{name, gone} {
		if err := os.WriteFile(filepath.Join(root, "History", file+".json"), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		tunnelHistoriesLock.Lock()
		delete(tunnelHistories, name)
		delete(tunnelHistories, gone)
		tunnelHistoriesLock.Unlock()
		trackedTunnelsLock.Lock()
		delete(trackedTunnelsMetrics, name)
		trackedTunnelsLock.Unlock()
	})

	loadTunnelHistories()

	if _, err := os.Stat(filepath.Join(root, "History", gone+".json")); !os.IsNotExist(err) {
		t.Errorf("history of a deleted tunnel kept: %v", err)
	}
	metrics := trackedTunnelMetrics(name)
	if !metrics.LastActiveEnd.Equal(clock.wall) || metrics.LastActiveDuration != 90*time.Second {
		t.Errorf("last active %v for %v", metrics.LastActiveEnd, metrics.LastActiveDuration)
	}
	history, enabled := trackedTunnelHistory(name)
	if !enabled || len(history.Sessions) != 2 || history.Sessions[1].EndedBy != SessionManagerStopped {
		t.Errorf("history %+v", history)
	}

	// A damaged file is not trusted: the tunnel starts with no history.
	const damaged = "history-damaged-test"
	os.WriteFile(filepath.Join(root, "History", damaged+".json"), contents[:20], 0o600)
	t.Cleanup(func() {
		tunnelHistoriesLock.Lock()
		delete(tunnelHistories, damaged)
		tunnelHistoriesLock.Unlock()
	})
	if history, _ := trackedTunnelHistory(damaged); len(history.Sessions)+len(history.Days) != 0 {
		t.Errorf("damaged history read: %+v", history)
	}
}
