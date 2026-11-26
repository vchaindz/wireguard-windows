/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
)

// SessionEnd says how a period of a tunnel being active ended.
type SessionEnd uint8

const (
	// SessionInProgress marks the session of a tunnel that is still active. Its End is the time of the latest
	// sample, and on disk the time it was last written.
	SessionInProgress SessionEnd = iota + 1
	// SessionDeactivated means that the tunnel was deactivated, or that its service stopped.
	SessionDeactivated
	// SessionManagerStopped means that the manager stopped, or crashed, while the tunnel was active. End is the
	// last time the session was written, so up to a minute may be missing.
	SessionManagerStopped
	// SessionSuspended means that samples stopped for much longer than they are taken, as when the computer
	// sleeps. End is the last sample before the gap; a new session begins after it.
	SessionSuspended
)

// TunnelSession is one finished, or the current, period of a tunnel being active.
type TunnelSession struct {
	// Start and End are wall-clock times, for display. They are not used to compute durations, as the clock may
	// have been changed in between.
	Start, End time.Time
	// ActiveSeconds and ConnectedSeconds are measured with a monotonic clock. Connected time is time with a
	// verified connection, counted as the connection check does: from a completed handshake until a peer is
	// found not to answer.
	ActiveSeconds, ConnectedSeconds uint32
	RxBytes, TxBytes                uint64
	ConnectionFailures              uint32
	Reconnects                      uint32
	// Endpoint is the endpoint of the first peer as configured when the session began, for the record.
	Endpoint string
	EndedBy  SessionEnd
}

// TunnelDayUsage is what a tunnel did on one local calendar day.
type TunnelDayUsage struct {
	// Day is local midnight of that day, with the time zone offset it had when it was recorded.
	Day                             time.Time
	RxBytes, TxBytes                uint64
	ActiveSeconds, ConnectedSeconds uint32
}

// TunnelHistory is what the manager keeps about a tunnel across its sessions.
type TunnelHistory struct {
	Sessions []TunnelSession  // oldest first; the last one may be in progress
	Days     []TunnelDayUsage // oldest first, each day at most once
}

const (
	maxHistorySessions = 500
	maxHistoryDays     = 400

	// historyGapLimit is how long samples may stop before the time is taken for a suspension rather than for a
	// slow sample. Samples are taken every five seconds at the slowest.
	historyGapLimit = 30 * time.Second
	// historySaveInterval is how often an active session is written, which is how much a crash can lose.
	historySaveInterval = time.Minute

	// maxEndpointLength fits a host name of the usual length, or a bracketed IPv6 address with a zone, and a port.
	maxEndpointLength = 255

	historyFormatVersion = 1
)

// recordedEndpoint is the endpoint as kept in the history: limited in length and to the characters of host
// names and addresses, so that the size of the file is known whatever the configuration holds.
func recordedEndpoint(endpoint string) string {
	kept := make([]byte, 0, min(len(endpoint), maxEndpointLength))
	for i := 0; i < len(endpoint) && len(kept) < maxEndpointLength; i++ {
		c := endpoint[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':' || c == '[' || c == ']' || c == '%' || c == '_' {
			kept = append(kept, c)
		}
	}
	return string(kept)
}

// dayKey numbers a calendar day so that later days have larger numbers.
func dayKey(t time.Time) int {
	year, month, day := t.Date()
	return year*10000 + int(month)*100 + day
}

func localMidnight(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

func addSeconds32(total *uint32, add time.Duration) {
	sum := uint64(*total) + uint64(add/time.Second)
	if sum > 0xffffffff {
		sum = 0xffffffff
	}
	*total = uint32(sum)
}

// counterDelta is how much a traffic counter grew. A counter that went down was reset, as when a peer is removed
// and added again, and has counted from zero since.
func counterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

// A historyRecorder turns the samples of one tunnel into its sessions and its usage per day. It is fed the wall
// time of each sample, for display and for telling days apart, and a monotonic time, from which every duration is
// taken, so that it can be tested with any clock.
type historyRecorder struct {
	history TunnelHistory
	// open is the session in progress, or nil while the tunnel is not active.
	open *TunnelSession

	// The latest sample of the open session.
	lastWall       time.Time
	lastMono       time.Duration
	lastRx, lastTx uint64

	connected, everConnected, failing bool
	lastSaveMono                      time.Duration

	// The session's times are kept exactly and written out in whole seconds. The days are kept in whole
	// seconds, with what is left of a second carried to the next interval.
	sessionActive, sessionConnected time.Duration
	dayActiveRest, dayConnectedRest time.Duration
}

func (r *historyRecorder) begin(wall time.Time, mono time.Duration, endpoint string) {
	r.open = &TunnelSession{Start: wall.Truncate(time.Second), End: wall.Truncate(time.Second), Endpoint: recordedEndpoint(endpoint), EndedBy: SessionInProgress}
	r.lastWall, r.lastMono, r.lastSaveMono = wall, mono, mono
	r.sessionActive, r.sessionConnected = 0, 0
	r.connected, r.everConnected, r.failing = false, false, false
}

// note counts failures and reconnects as metricsRecorder does. A tunnel that is merely idle, so that its
// connection cannot be verified, keeps counting as connected until a peer is found not to answer.
func (r *historyRecorder) note(health TunnelHealth) {
	switch {
	case health == TunnelHealthConnected:
		if !r.connected {
			if r.everConnected {
				r.open.Reconnects++
			}
			r.connected, r.everConnected = true, true
		}
		r.failing = false
	case health.IsNoConnection():
		if !r.failing {
			r.open.ConnectionFailures++
			r.failing = true
		}
		r.connected = false
	}
}

// day returns the usage of the day that begins at midnight, adding it in order if it is not kept yet. A day older
// than all of a full list is not kept, and gets a record that is thrown away.
func (r *historyRecorder) day(midnight time.Time) *TunnelDayUsage {
	key := dayKey(midnight)
	days := r.history.Days
	i := len(days)
	for i > 0 && dayKey(days[i-1].Day) >= key {
		i--
		if dayKey(days[i].Day) == key {
			return &r.history.Days[i]
		}
	}
	if len(days) >= maxHistoryDays {
		if i == 0 {
			return new(TunnelDayUsage)
		}
		days = days[1:]
		i--
	}
	days = append(days, TunnelDayUsage{})
	copy(days[i+1:], days[i:])
	days[i] = TunnelDayUsage{Day: midnight}
	r.history.Days = days
	return &r.history.Days[i]
}

// addToDays attributes an interval of activity that ended at wall, and the traffic in it, to the days it covers,
// splitting both at local midnight in proportion to time.
func (r *historyRecorder) addToDays(wall time.Time, elapsed time.Duration, rx, tx uint64, connected bool) {
	if elapsed <= 0 {
		day := r.day(localMidnight(wall))
		day.RxBytes += rx
		day.TxBytes += tx
		return
	}
	start := wall.Add(-elapsed)
	restRx, restTx := rx, tx
	for start.Before(wall) {
		midnight := localMidnight(start)
		end := midnight.AddDate(0, 0, 1)
		if !end.Before(wall) {
			end = wall
		}
		piece := end.Sub(start)
		pieceRx, pieceTx := restRx, restTx
		if end.Before(wall) {
			share := float64(piece) / float64(elapsed)
			pieceRx, pieceTx = min(uint64(float64(rx)*share), restRx), min(uint64(float64(tx)*share), restTx)
		}
		restRx, restTx = restRx-pieceRx, restTx-pieceTx
		day := r.day(midnight)
		day.RxBytes += pieceRx
		day.TxBytes += pieceTx
		r.dayActiveRest += piece
		addSeconds32(&day.ActiveSeconds, r.dayActiveRest)
		r.dayActiveRest %= time.Second
		if connected {
			r.dayConnectedRest += piece
			addSeconds32(&day.ConnectedSeconds, r.dayConnectedRest)
			r.dayConnectedRest %= time.Second
		}
		start = end
	}
}

// addInterval counts the time since the latest sample, and the traffic in it, for the open session and its days.
func (r *historyRecorder) addInterval(wall time.Time, elapsed time.Duration, rx, tx uint64) {
	r.sessionActive += elapsed
	if r.connected {
		r.sessionConnected += elapsed
	}
	r.open.RxBytes += rx
	r.open.TxBytes += tx
	r.syncSeconds()
	r.addToDays(wall, elapsed, rx, tx, r.connected)
}

func (r *historyRecorder) syncSeconds() {
	r.open.ActiveSeconds, r.open.ConnectedSeconds = 0, 0
	addSeconds32(&r.open.ActiveSeconds, r.sessionActive)
	addSeconds32(&r.open.ConnectedSeconds, r.sessionConnected)
}

// finish closes the open session. A session cut short by a suspension before anything happened in it is not
// worth a record.
func (r *historyRecorder) finish(end SessionEnd, at time.Time) {
	if r.open == nil {
		return
	}
	session := *r.open
	r.open = nil
	session.EndedBy = end
	session.End = at.Truncate(time.Second)
	if end == SessionSuspended && session.ActiveSeconds == 0 && session.RxBytes == 0 && session.TxBytes == 0 {
		return
	}
	r.history.Sessions = append(r.history.Sessions, session)
	if extra := len(r.history.Sessions) - maxHistorySessions; extra > 0 {
		r.history.Sessions = append(r.history.Sessions[:0:0], r.history.Sessions[extra:]...)
	}
}

// observe records a sample of an active tunnel: the traffic counters summed over its peers and its health. The
// first sample of a session only sets where the counters start, as the traffic before it may belong to a session
// that was already recorded, when the manager restarted while the tunnel was active. It reports whether the
// history should be written now.
func (r *historyRecorder) observe(wall time.Time, mono time.Duration, rx, tx uint64, health TunnelHealth, endpoint string) (save bool) {
	wall = wall.Round(0)
	if r.open == nil {
		r.begin(wall, mono, endpoint)
		r.lastRx, r.lastTx = rx, tx
		r.note(health)
		return false
	}
	elapsed := max(mono-r.lastMono, 0)
	rxDelta, txDelta := counterDelta(r.lastRx, rx), counterDelta(r.lastTx, tx)
	if elapsed > historyGapLimit {
		// The computer slept, or the manager could not sample for a long time. Nothing is known about the gap,
		// so it counts neither as active nor as connected time; the traffic in it goes to the new session.
		r.finish(SessionSuspended, r.lastWall)
		r.begin(wall, mono, endpoint)
		r.addInterval(wall, 0, rxDelta, txDelta)
		save = true
	} else {
		r.addInterval(wall, elapsed, rxDelta, txDelta)
	}
	r.note(health)
	r.lastWall, r.lastMono, r.lastRx, r.lastTx = wall, mono, rx, tx
	r.open.End = wall.Truncate(time.Second)
	if save || mono-r.lastSaveMono >= historySaveInterval {
		r.lastSaveMono = mono
		return true
	}
	return false
}

// stop closes the open session because the tunnel stopped. It reports whether there was one, which then needs to be
// written.
func (r *historyRecorder) stop(wall time.Time, mono time.Duration) bool {
	if r.open == nil {
		return false
	}
	wall = wall.Round(0)
	elapsed := max(mono-r.lastMono, 0)
	if elapsed > historyGapLimit {
		r.finish(SessionSuspended, r.lastWall)
		return true
	}
	r.addInterval(wall, elapsed, 0, 0)
	r.finish(SessionDeactivated, wall)
	return true
}

// abandon forgets the open session without recording it, for when policy disables the history.
func (r *historyRecorder) abandon() {
	r.open = nil
}

// clear forgets all of the history. An open session starts afresh at the latest sample, so that what came before
// the clearing is not recorded later.
func (r *historyRecorder) clear() {
	r.history = TunnelHistory{}
	r.dayActiveRest, r.dayConnectedRest = 0, 0
	if r.open != nil {
		r.begin(r.lastWall, r.lastMono, r.open.Endpoint)
	}
}

// snapshot returns a copy of the history with the open session, if any, as the last one.
func (r *historyRecorder) snapshot() TunnelHistory {
	sessions := r.history.Sessions
	if r.open != nil {
		sessions = append(sessions[:len(sessions):len(sessions)], *r.open)
	}
	if extra := len(sessions) - maxHistorySessions; extra > 0 {
		sessions = sessions[extra:]
	}
	return TunnelHistory{
		Sessions: append([]TunnelSession(nil), sessions...),
		Days:     append([]TunnelDayUsage(nil), r.history.Days...),
	}
}

// lastFinished is the most recent session that has ended, or nil.
func (r *historyRecorder) lastFinished() *TunnelSession {
	if n := len(r.history.Sessions); n > 0 {
		return &r.history.Sessions[n-1]
	}
	return nil
}

// historyFile is the stored form of a TunnelHistory. Its version changes whenever the meaning of a field does; a
// file of another version is not read.
type historyFile struct {
	Version  int
	Sessions []TunnelSession
	Days     []TunnelDayUsage
}

func marshalTunnelHistory(history TunnelHistory) ([]byte, error) {
	contents, err := json.Marshal(historyFile{Version: historyFormatVersion, Sessions: history.Sessions, Days: history.Days})
	if err != nil {
		return nil, err
	}
	if len(contents) > conf.MaxTunnelHistorySize {
		return nil, errors.New("Connection history is too large")
	}
	return contents, nil
}

// parseTunnelHistory reads a stored history. Anything that this version would not have written makes the whole
// file invalid, so that the file is replaced rather than trusted. A session that was in progress when it was
// written is closed as ended by the manager stopping, at the time it was written.
func parseTunnelHistory(contents []byte) (TunnelHistory, error) {
	var file historyFile
	if err := json.Unmarshal(contents, &file); err != nil {
		return TunnelHistory{}, err
	}
	if file.Version != historyFormatVersion {
		return TunnelHistory{}, errors.New("Connection history has an unknown version")
	}
	if len(file.Sessions) > maxHistorySessions || len(file.Days) > maxHistoryDays {
		return TunnelHistory{}, errors.New("Connection history has too many entries")
	}
	for i := range file.Sessions {
		session := &file.Sessions[i]
		if session.Start.IsZero() || session.End.IsZero() || session.EndedBy < SessionInProgress || session.EndedBy > SessionSuspended || recordedEndpoint(session.Endpoint) != session.Endpoint {
			return TunnelHistory{}, errors.New("Connection history has an invalid session")
		}
		if session.EndedBy == SessionInProgress {
			session.EndedBy = SessionManagerStopped
		}
	}
	for i := range file.Days {
		if file.Days[i].Day.IsZero() || i > 0 && dayKey(file.Days[i].Day) <= dayKey(file.Days[i-1].Day) {
			return TunnelHistory{}, errors.New("Connection history has an invalid day")
		}
	}
	return TunnelHistory{Sessions: file.Sessions, Days: file.Days}, nil
}

// historyAllowed reports whether policy permits keeping connection history at all.
func historyAllowed() bool {
	return !conf.AdminBool("DisableConnectionHistory")
}

// The recorders of all tunnels whose history was needed since the manager started. A recorder is loaded from disk
// on first use, which is also when a session left open by a previous run of the manager is closed: the manager has
// not written anything for that tunnel yet, so whatever is open on disk is from before.
var (
	tunnelHistoriesLock sync.Mutex
	tunnelHistories     = make(map[string]*historyRecorder)
	// historyClockBase is what the monotonic times given to the recorders count from.
	historyClockBase = time.Now()
)

// historyMono is a monotonic reading of now. Time.Sub uses the monotonic clock when both times have one, which
// those from time.Now do; on Windows it keeps running while the computer sleeps, so a sleep shows as a gap.
func historyMono(now time.Time) time.Duration {
	return now.Sub(historyClockBase)
}

// loadedHistoryRecorder returns the recorder of a tunnel, reading its history the first time. It must be called
// with tunnelHistoriesLock held.
func loadedHistoryRecorder(tunnelName string) *historyRecorder {
	if recorder := tunnelHistories[tunnelName]; recorder != nil {
		return recorder
	}
	recorder := new(historyRecorder)
	contents, err := conf.LoadTunnelHistory(tunnelName)
	if err == nil {
		recorder.history, err = parseTunnelHistory(contents)
	}
	if err != nil && !os.IsNotExist(err) {
		log.Printf("[%s] Warning: unable to read connection history, starting a new one: %v", tunnelName, err)
	}
	tunnelHistories[tunnelName] = recorder
	return recorder
}

// saveHistoryLocked writes the history of a tunnel, with its open session. It must be called with
// tunnelHistoriesLock held, which also keeps two writes of the same file apart.
func saveHistoryLocked(tunnelName string, recorder *historyRecorder) {
	contents, err := marshalTunnelHistory(recorder.snapshot())
	if err == nil {
		err = conf.SaveTunnelHistory(tunnelName, contents)
	}
	if err != nil {
		log.Printf("[%s] Warning: unable to write connection history: %v", tunnelName, err)
	}
}

// historyObserve records a sample of an active tunnel, and writes its history when a session ended or a minute
// has passed since it was last written.
func historyObserve(tunnelName, endpoint string, now time.Time, rx, tx uint64, health TunnelHealth) {
	allowed := historyAllowed()
	tunnelHistoriesLock.Lock()
	defer tunnelHistoriesLock.Unlock()
	if !allowed {
		if recorder := tunnelHistories[tunnelName]; recorder != nil {
			recorder.abandon()
		}
		return
	}
	recorder := loadedHistoryRecorder(tunnelName)
	if recorder.observe(now, historyMono(now), rx, tx, health, endpoint) {
		saveHistoryLocked(tunnelName, recorder)
	}
}

// historyStopped closes the session of a tunnel that stopped and writes its history.
func historyStopped(tunnelName string, now time.Time) {
	allowed := historyAllowed()
	tunnelHistoriesLock.Lock()
	defer tunnelHistoriesLock.Unlock()
	recorder := tunnelHistories[tunnelName]
	if recorder == nil || !recorder.stop(now, historyMono(now)) || !allowed {
		return
	}
	saveHistoryLocked(tunnelName, recorder)
}

// flushTunnelHistories writes the open sessions when the manager stops, so that the next start closes them at
// the time the manager stopped rather than up to a minute before.
func flushTunnelHistories() {
	if !historyAllowed() {
		return
	}
	tunnelHistoriesLock.Lock()
	defer tunnelHistoriesLock.Unlock()
	for name, recorder := range tunnelHistories {
		if recorder.open != nil {
			saveHistoryLocked(name, recorder)
		}
	}
}

// trackedTunnelHistory returns the history of a tunnel, and false instead if policy disables history.
func trackedTunnelHistory(tunnelName string) (TunnelHistory, bool) {
	if !historyAllowed() {
		return TunnelHistory{}, false
	}
	tunnelHistoriesLock.Lock()
	defer tunnelHistoriesLock.Unlock()
	return loadedHistoryRecorder(tunnelName).snapshot(), true
}

// clearTunnelHistory deletes the history of a tunnel, and with it when it was last active.
func clearTunnelHistory(tunnelName string) error {
	if !conf.TunnelNameIsValid(tunnelName) {
		return errors.New("Tunnel name is not valid")
	}
	tunnelHistoriesLock.Lock()
	if recorder := tunnelHistories[tunnelName]; recorder != nil {
		recorder.clear()
	}
	err := conf.DeleteTunnelHistory(tunnelName)
	tunnelHistoriesLock.Unlock()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	withTunnelMetrics(tunnelName, func(r *metricsRecorder) {
		r.metrics.LastActiveEnd, r.metrics.LastActiveDuration = time.Time{}, 0
	})
	log.Printf("[%s] Connection history cleared", tunnelName)
	return nil
}

// loadTunnelHistories runs when the manager starts, before it tracks any tunnel. It removes the history of
// tunnels that no longer exist, and tells the metrics when each tunnel was last active, which they would
// otherwise have forgotten with the previous run of the manager. Failure and reconnect counters are not seeded:
// they describe this run of the manager, and the sessions keep their own.
func loadTunnelHistories() {
	removeOrphanedTunnelFiles(conf.ListTunnelHistoryNames, conf.DeleteTunnelHistory, "connection history")
	if !historyAllowed() {
		return
	}
	names, err := conf.ListTunnelHistoryNames()
	if err != nil {
		return
	}
	for _, name := range names {
		tunnelHistoriesLock.Lock()
		var last TunnelSession
		found := false
		if session := loadedHistoryRecorder(name).lastFinished(); session != nil {
			last, found = *session, true
		}
		tunnelHistoriesLock.Unlock()
		if !found {
			continue
		}
		withTunnelMetrics(name, func(r *metricsRecorder) {
			if r.metrics.LastActiveEnd.IsZero() {
				r.metrics.LastActiveEnd = last.End
				r.metrics.LastActiveDuration = time.Duration(last.ActiveSeconds) * time.Second
			}
		})
	}
}
