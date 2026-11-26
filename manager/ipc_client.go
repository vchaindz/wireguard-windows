/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"encoding/gob"
	"errors"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/updater"
)

type Tunnel struct {
	Name string
}

type TunnelState int

const (
	TunnelUnknown TunnelState = iota
	TunnelStarted
	TunnelStopped
	TunnelStarting
	TunnelStopping
)

type NotificationType int

const (
	TunnelChangeNotificationType NotificationType = iota
	TunnelsChangeNotificationType
	ManagerStoppingNotificationType
	UpdateFoundNotificationType
	UpdateProgressNotificationType
	TunnelHealthNotificationType
)

type MethodType int

const (
	StoredConfigMethodType MethodType = iota
	RuntimeConfigMethodType
	StartMethodType
	StopMethodType
	WaitForStopMethodType
	DeleteMethodType
	StateMethodType
	GlobalStateMethodType
	CreateMethodType
	TunnelsMethodType
	QuitMethodType
	UpdateStateMethodType
	UpdateMethodType
	HealthMethodType
	MetricsMethodType
	WatchMethodType
	SamplesMethodType
	SettingsMethodType
	SetSettingsMethodType
	HistoryMethodType
	ClearHistoryMethodType
	PathMethodType
	StartDiagnosisMethodType
	DiagnosisMethodType
)

var (
	rpcEncoder *gob.Encoder
	rpcDecoder *gob.Decoder
	rpcMutex   sync.Mutex
)

type TunnelChangeCallback struct {
	cb func(tunnel *Tunnel, state, globalState TunnelState, err error)
}

var (
	tunnelChangeCallbacks     = make(map[*TunnelChangeCallback]bool)
	tunnelChangeCallbacksLock sync.RWMutex
)

type TunnelHealthCallback struct {
	cb func(tunnel *Tunnel, health TunnelHealth, conflictSuspected, unstable bool)
}

var (
	tunnelHealthCallbacks     = make(map[*TunnelHealthCallback]bool)
	tunnelHealthCallbacksLock sync.RWMutex
)

type TunnelsChangeCallback struct {
	cb func()
}

var (
	tunnelsChangeCallbacks     = make(map[*TunnelsChangeCallback]bool)
	tunnelsChangeCallbacksLock sync.RWMutex
)

type ManagerStoppingCallback struct {
	cb func()
}

var (
	managerStoppingCallbacks     = make(map[*ManagerStoppingCallback]bool)
	managerStoppingCallbacksLock sync.RWMutex
)

type UpdateFoundCallback struct {
	cb func(updateState UpdateState)
}

var (
	updateFoundCallbacks     = make(map[*UpdateFoundCallback]bool)
	updateFoundCallbacksLock sync.RWMutex
)

type UpdateProgressCallback struct {
	cb func(dp updater.DownloadProgress)
}

var (
	updateProgressCallbacks     = make(map[*UpdateProgressCallback]bool)
	updateProgressCallbacksLock sync.RWMutex
)

func InitializeIPCClient(reader, writer, events *os.File) {
	rpcDecoder = gob.NewDecoder(reader)
	rpcEncoder = gob.NewEncoder(writer)
	go func() {
		decoder := gob.NewDecoder(events)
		for {
			var notificationType NotificationType
			err := decoder.Decode(&notificationType)
			if err != nil {
				return
			}
			switch notificationType {
			case TunnelChangeNotificationType:
				var tunnel string
				err := decoder.Decode(&tunnel)
				if err != nil {
					return
				}
				var state TunnelState
				err = decoder.Decode(&state)
				if err != nil {
					return
				}
				var globalState TunnelState
				err = decoder.Decode(&globalState)
				if err != nil {
					return
				}
				var errStr string
				err = decoder.Decode(&errStr)
				if err != nil {
					return
				}
				var retErr error
				if len(errStr) > 0 {
					retErr = errors.New(errStr)
				}
				if len(tunnel) == 0 || state == TunnelUnknown {
					continue
				}
				t := &Tunnel{tunnel}
				tunnelChangeCallbacksLock.RLock()
				for cb := range tunnelChangeCallbacks {
					cb.cb(t, state, globalState, retErr)
				}
				tunnelChangeCallbacksLock.RUnlock()
			case TunnelsChangeNotificationType:
				tunnelsChangeCallbacksLock.RLock()
				for cb := range tunnelsChangeCallbacks {
					cb.cb()
				}
				tunnelsChangeCallbacksLock.RUnlock()
			case ManagerStoppingNotificationType:
				managerStoppingCallbacksLock.RLock()
				for cb := range managerStoppingCallbacks {
					cb.cb()
				}
				managerStoppingCallbacksLock.RUnlock()
			case UpdateFoundNotificationType:
				var state UpdateState
				err = decoder.Decode(&state)
				if err != nil {
					return
				}
				updateFoundCallbacksLock.RLock()
				for cb := range updateFoundCallbacks {
					cb.cb(state)
				}
				updateFoundCallbacksLock.RUnlock()
			case UpdateProgressNotificationType:
				var dp updater.DownloadProgress
				err = decoder.Decode(&dp.Activity)
				if err != nil {
					return
				}
				err = decoder.Decode(&dp.BytesDownloaded)
				if err != nil {
					return
				}
				err = decoder.Decode(&dp.BytesTotal)
				if err != nil {
					return
				}
				var errStr string
				err = decoder.Decode(&errStr)
				if err != nil {
					return
				}
				if len(errStr) > 0 {
					dp.Error = errors.New(errStr)
				}
				err = decoder.Decode(&dp.Complete)
				if err != nil {
					return
				}
				updateProgressCallbacksLock.RLock()
				for cb := range updateProgressCallbacks {
					cb.cb(dp)
				}
				updateProgressCallbacksLock.RUnlock()
			case TunnelHealthNotificationType:
				var tunnel string
				err := decoder.Decode(&tunnel)
				if err != nil {
					return
				}
				var health TunnelHealth
				err = decoder.Decode(&health)
				if err != nil {
					return
				}
				var conflictSuspected bool
				err = decoder.Decode(&conflictSuspected)
				if err != nil {
					return
				}
				var unstable bool
				err = decoder.Decode(&unstable)
				if err != nil {
					return
				}
				if len(tunnel) == 0 {
					continue
				}
				t := &Tunnel{tunnel}
				tunnelHealthCallbacksLock.RLock()
				for cb := range tunnelHealthCallbacks {
					cb.cb(t, health, conflictSuspected, unstable)
				}
				tunnelHealthCallbacksLock.RUnlock()
			}
		}
	}()
}

func rpcDecodeError() error {
	var str string
	err := rpcDecoder.Decode(&str)
	if err != nil {
		return err
	}
	if len(str) == 0 {
		return nil
	}
	return errors.New(str)
}

func (t *Tunnel) StoredConfig() (c conf.Config, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StoredConfigMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&c)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) RuntimeConfig() (c conf.Config, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(RuntimeConfigMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&c)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) Start() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StartMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) Stop() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StopMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) Toggle() (oldState TunnelState, err error) {
	oldState, err = t.State()
	if err != nil {
		oldState = TunnelUnknown
		return
	}
	if oldState == TunnelStarted {
		err = t.Stop()
	} else if oldState == TunnelStopped {
		err = t.Start()
	}
	return
}

func (t *Tunnel) WaitForStop() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(WaitForStopMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) Delete() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(DeleteMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) State() (tunnelState TunnelState, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StateMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnelState)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// Health reports whether the started tunnel has a working session, whether another device is suspected of using
// the same private key, and whether the connection was lost and re-established recently. It is
// TunnelHealthUnknown for a tunnel that is not started.
func (t *Tunnel) Health() (health TunnelHealth, conflictSuspected, unstable bool, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(HealthMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&health)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&conflictSuspected)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&unstable)
	return
}

// Metrics returns what the manager has observed about the tunnel since the manager started: how
// long it has been active and connected, when it was last active, and its failure counters.
func (t *Tunnel) Metrics() (metrics TunnelMetrics, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(MetricsMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&metrics)
	return
}

// Samples returns the tunnel's samples newer than since, oldest first, at the given resolution; a zero since
// returns all that are kept. A tunnel that is not started has none. The minute that is still running is only in
// the per-second samples.
func (t *Tunnel) Samples(resolution SampleResolution, since time.Time) (samples []TunnelSample, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(SamplesMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(resolution)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(since)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&samples)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// Settings returns the tunnel's settings, and whether policy allows measuring connection quality at all.
func (t *Tunnel) Settings() (settings TunnelSettings, probingAllowed bool, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(SettingsMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&settings)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&probingAllowed)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// SetSettings stores the tunnel's settings. It takes effect on a running tunnel at its next sample. Only
// administrators may change settings.
func (t *Tunnel) SetSettings(settings TunnelSettings) (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(SetSettingsMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(settings)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// History returns the tunnel's past sessions, with the current one last if it is active, and its usage per day.
// enabled is false, and the history empty, when policy disables connection history.
func (t *Tunnel) History() (history TunnelHistory, enabled bool, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(HistoryMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&history)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&enabled)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// ClearHistory deletes the tunnel's history, and with it when it was last active. Only administrators may clear
// history.
func (t *Tunnel) ClearHistory() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(ClearHistoryMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// Path describes how the started tunnel reaches its peers: the endpoint addresses in use, the interfaces that
// carry them, and the MTUs. It is empty for a tunnel that is not started.
func (t *Tunnel) Path() (path TunnelPath, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(PathMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&path)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

// diagnosisPollInterval is how often a running test is asked for its progress.
const diagnosisPollInterval = 300 * time.Millisecond

// Diagnose tests the started tunnel step by step and returns the result of each step. It takes seconds. Only one
// test of a tunnel runs at a time, and another may start only a few seconds after the last one ended.
func (t *Tunnel) Diagnose() (steps []DiagnosisStep, err error) {
	return t.DiagnoseWithProgress(nil)
}

// DiagnoseWithProgress is Diagnose, calling progress with the steps finished so far whenever it learns of more.
// The test runs in the manager, and is polled for, so that the connection to the manager is not held for the
// seconds it takes and other requests go on meanwhile.
func (t *Tunnel) DiagnoseWithProgress(progress func(steps []DiagnosisStep)) (steps []DiagnosisStep, err error) {
	if err = t.startDiagnosis(); err != nil {
		return
	}
	reported := 0
	for {
		time.Sleep(diagnosisPollInterval)
		var running bool
		steps, running, err = t.diagnosis()
		if err != nil {
			return
		}
		if progress != nil && len(steps) != reported {
			reported = len(steps)
			progress(steps)
		}
		if !running {
			return
		}
	}
}

func (t *Tunnel) startDiagnosis() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StartDiagnosisMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) diagnosis() (steps []DiagnosisStep, running bool, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(DiagnosisMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&steps)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&running)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientGlobalState() (tunnelState TunnelState, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(GlobalStateMethodType)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnelState)
	if err != nil {
		return
	}
	return
}

func IPCClientNewTunnel(conf *conf.Config) (tunnel Tunnel, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(CreateMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(*conf)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnel)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientTunnels() (tunnels []Tunnel, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(TunnelsMethodType)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnels)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientQuit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(QuitMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(stopTunnelsOnQuit)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&alreadyQuit)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientUpdateState() (updateState UpdateState, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(UpdateStateMethodType)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&updateState)
	if err != nil {
		return
	}
	return
}

// IPCClientWatch tells the manager whether this UI is showing live data, so that it samples tunnels every
// second while it does. The manager forgets the hint when the connection ends.
func IPCClientWatch(watching bool) error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(WatchMethodType)
	if err != nil {
		return err
	}
	return rpcEncoder.Encode(watching)
}

func IPCClientUpdate() error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	return rpcEncoder.Encode(UpdateMethodType)
}

func IPCClientRegisterTunnelChange(cb func(tunnel *Tunnel, state, globalState TunnelState, err error)) *TunnelChangeCallback {
	s := &TunnelChangeCallback{cb}
	tunnelChangeCallbacksLock.Lock()
	tunnelChangeCallbacks[s] = true
	tunnelChangeCallbacksLock.Unlock()
	return s
}

func (cb *TunnelChangeCallback) Unregister() {
	tunnelChangeCallbacksLock.Lock()
	delete(tunnelChangeCallbacks, cb)
	tunnelChangeCallbacksLock.Unlock()
}

func IPCClientRegisterTunnelHealth(cb func(tunnel *Tunnel, health TunnelHealth, conflictSuspected, unstable bool)) *TunnelHealthCallback {
	s := &TunnelHealthCallback{cb}
	tunnelHealthCallbacksLock.Lock()
	tunnelHealthCallbacks[s] = true
	tunnelHealthCallbacksLock.Unlock()
	return s
}

func (cb *TunnelHealthCallback) Unregister() {
	tunnelHealthCallbacksLock.Lock()
	delete(tunnelHealthCallbacks, cb)
	tunnelHealthCallbacksLock.Unlock()
}

func IPCClientRegisterTunnelsChange(cb func()) *TunnelsChangeCallback {
	s := &TunnelsChangeCallback{cb}
	tunnelsChangeCallbacksLock.Lock()
	tunnelsChangeCallbacks[s] = true
	tunnelsChangeCallbacksLock.Unlock()
	return s
}

func (cb *TunnelsChangeCallback) Unregister() {
	tunnelsChangeCallbacksLock.Lock()
	delete(tunnelsChangeCallbacks, cb)
	tunnelsChangeCallbacksLock.Unlock()
}

func IPCClientRegisterManagerStopping(cb func()) *ManagerStoppingCallback {
	s := &ManagerStoppingCallback{cb}
	managerStoppingCallbacksLock.Lock()
	managerStoppingCallbacks[s] = true
	managerStoppingCallbacksLock.Unlock()
	return s
}

func (cb *ManagerStoppingCallback) Unregister() {
	managerStoppingCallbacksLock.Lock()
	delete(managerStoppingCallbacks, cb)
	managerStoppingCallbacksLock.Unlock()
}

func IPCClientRegisterUpdateFound(cb func(updateState UpdateState)) *UpdateFoundCallback {
	s := &UpdateFoundCallback{cb}
	updateFoundCallbacksLock.Lock()
	updateFoundCallbacks[s] = true
	updateFoundCallbacksLock.Unlock()
	return s
}

func (cb *UpdateFoundCallback) Unregister() {
	updateFoundCallbacksLock.Lock()
	delete(updateFoundCallbacks, cb)
	updateFoundCallbacksLock.Unlock()
}

func IPCClientRegisterUpdateProgress(cb func(dp updater.DownloadProgress)) *UpdateProgressCallback {
	s := &UpdateProgressCallback{cb}
	updateProgressCallbacksLock.Lock()
	updateProgressCallbacks[s] = true
	updateProgressCallbacksLock.Unlock()
	return s
}

func (cb *UpdateProgressCallback) Unregister() {
	updateProgressCallbacksLock.Lock()
	delete(updateProgressCallbacks, cb)
	updateProgressCallbacksLock.Unlock()
}
