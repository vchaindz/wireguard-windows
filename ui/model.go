/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// A tunnelEntry is what the UI knows about one tunnel.
type tunnelEntry struct {
	tunnel            manager.Tunnel
	state             manager.TunnelState
	health            manager.TunnelHealth
	conflictSuspected bool
	unstable          bool
	// config is the runtime configuration of a started tunnel, or the stored one of the tunnel whose details are shown.
	config *conf.Config
	// metrics is what the manager has observed about the tunnel since the manager started.
	metrics manager.TunnelMetrics
}

func (entry *tunnelEntry) active() bool {
	return entry.state == manager.TunnelStarted || entry.state == manager.TunnelStarting || entry.state == manager.TunnelStopping
}

// The appModel holds the tunnels as the manager reports them and performs the actions on them. Its
// fields are read and written on the UI thread only; a single worker goroutine talks to the manager.
type appModel struct {
	entries         []tunnelEntry
	globalState     manager.TunnelState
	updateAvailable bool
	// lastUsed is the tunnel that was most recently toggled, offered for activation when none is active.
	lastUsed string
	// traffic holds the traffic rates of the started tunnels, by name.
	traffic map[string]*trafficHistory

	synchronize func(func())
	changed     []func()

	refreshRequests chan struct{}
	// fullRefreshPending is set when the next refresh has to reload everything, not only the counters.
	fullRefreshPending int32
	detailsLock        sync.Mutex
	detailsName        string

	tunnelChangedCB  *manager.TunnelChangeCallback
	tunnelHealthCB   *manager.TunnelHealthCallback
	tunnelsChangedCB *manager.TunnelsChangeCallback
	disposeOnce      sync.Once
}

func newAppModel(synchronize func(func())) *appModel {
	model := &appModel{
		synchronize:     synchronize,
		refreshRequests: make(chan struct{}, 1),
	}
	go func() {
		// The tunnels that the last full load found started; only these have counters worth updating.
		var started []manager.Tunnel
		for range model.refreshRequests {
			if atomic.SwapInt32(&model.fullRefreshPending, 0) != 0 {
				entries, globalState := model.load()
				started = started[:0]
				for i := range entries {
					if entries[i].state == manager.TunnelStarted {
						started = append(started, entries[i].tunnel)
					}
				}
				model.synchronize(func() {
					model.entries, model.globalState = entries, globalState
					model.recordTraffic(time.Now())
					model.notifyChanged()
				})
				continue
			}
			if len(started) == 0 {
				continue
			}
			type counters struct {
				config  *conf.Config
				metrics manager.TunnelMetrics
			}
			fresh := make(map[string]counters, len(started))
			for _, tunnel := range started {
				if config, err := tunnel.RuntimeConfig(); err == nil {
					metrics, _ := tunnel.Metrics()
					fresh[tunnel.Name] = counters{&config, metrics}
				}
			}
			model.synchronize(func() {
				for i := range model.entries {
					entry := &model.entries[i]
					if update, ok := fresh[entry.tunnel.Name]; ok && entry.state == manager.TunnelStarted {
						entry.config, entry.metrics = update.config, update.metrics
					}
				}
				model.recordTraffic(time.Now())
				model.notifyChanged()
			})
		}
	}()
	// What a notification says is shown at once; a state change is followed by a full reload, which also
	// picks up the runtime configuration of a tunnel that has just started.
	model.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(func(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
		name := tunnel.Name
		model.synchronize(func() {
			model.globalState = globalState
			if entry := model.entry(name); entry != nil && entry.state != state {
				entry.state = state
				if state != manager.TunnelStarted {
					entry.health, entry.conflictSuspected, entry.unstable = manager.TunnelHealthUnknown, false, false
				}
			}
			model.notifyChanged()
		})
		model.refresh()
	})
	model.tunnelHealthCB = manager.IPCClientRegisterTunnelHealth(func(tunnel *manager.Tunnel, health manager.TunnelHealth, conflictSuspected, unstable bool) {
		name := tunnel.Name
		model.synchronize(func() {
			if entry := model.entry(name); entry != nil && entry.state == manager.TunnelStarted {
				entry.health, entry.conflictSuspected, entry.unstable = health, conflictSuspected, unstable
				model.notifyChanged()
			}
		})
	})
	model.tunnelsChangedCB = manager.IPCClientRegisterTunnelsChange(model.refresh)
	model.refresh()
	return model
}

// dispose may be called more than once: destroying the window disposes of it a second time.
func (model *appModel) dispose() {
	model.disposeOnce.Do(func() {
		model.tunnelChangedCB.Unregister()
		model.tunnelHealthCB.Unregister()
		model.tunnelsChangedCB.Unregister()
		close(model.refreshRequests)
	})
}

// onChanged registers a function that is called on the UI thread whenever the tunnels were reloaded.
func (model *appModel) onChanged(changed func()) {
	model.changed = append(model.changed, changed)
}

// recordTraffic feeds the counters of the started tunnels into their traffic histories and forgets
// the histories of the others.
func (model *appModel) recordTraffic(now time.Time) {
	if model.traffic == nil {
		model.traffic = make(map[string]*trafficHistory)
	}
	started := make(map[string]bool, len(model.entries))
	for i := range model.entries {
		entry := &model.entries[i]
		if entry.state != manager.TunnelStarted || entry.config == nil {
			continue
		}
		name := entry.tunnel.Name
		started[name] = true
		history := model.traffic[name]
		if history == nil {
			history = new(trafficHistory)
			model.traffic[name] = history
		}
		_, rx, tx := trafficOf(entry.config)
		history.record(now, rx, tx)
	}
	for name := range model.traffic {
		if !started[name] {
			delete(model.traffic, name)
		}
	}
}

func (model *appModel) notifyChanged() {
	for _, changed := range model.changed {
		changed()
	}
}

// refresh asks the worker to reload the tunnels. It never blocks and may be called from any goroutine.
func (model *appModel) refresh() {
	atomic.StoreInt32(&model.fullRefreshPending, 1)
	model.refreshCounters()
}

// refreshCounters asks the worker to reload only what changes while a tunnel runs: the handshake times
// and traffic counters of the started tunnels.
func (model *appModel) refreshCounters() {
	defer func() { recover() }() // The model may have been disposed of meanwhile.
	select {
	case model.refreshRequests <- struct{}{}:
	default:
	}
}

// showDetailsOf makes the model also load the stored configuration of a tunnel that is not active.
func (model *appModel) showDetailsOf(name string) {
	model.detailsLock.Lock()
	model.detailsName = name
	model.detailsLock.Unlock()
	model.refresh()
}

func (model *appModel) load() (entries []tunnelEntry, globalState manager.TunnelState) {
	model.detailsLock.Lock()
	detailsName := model.detailsName
	model.detailsLock.Unlock()

	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return nil, manager.TunnelUnknown
	}
	sort.SliceStable(tunnels, func(i, j int) bool {
		return conf.TunnelNameIsLess(tunnels[i].Name, tunnels[j].Name)
	})
	entries = make([]tunnelEntry, 0, len(tunnels))
	for _, tunnel := range tunnels {
		entry := tunnelEntry{tunnel: tunnel}
		if entry.state, err = tunnel.State(); err != nil {
			entry.state = manager.TunnelUnknown
		}
		entry.metrics, _ = tunnel.Metrics()
		if entry.state == manager.TunnelStarted {
			entry.health, entry.conflictSuspected, entry.unstable, _ = tunnel.Health()
			if config, err := tunnel.RuntimeConfig(); err == nil {
				entry.config = &config
			}
		}
		if entry.config == nil && tunnel.Name == detailsName {
			if config, err := tunnel.StoredConfig(); err == nil {
				entry.config = &config
			}
		}
		entries = append(entries, entry)
	}
	if globalState, err = manager.IPCClientGlobalState(); err != nil {
		globalState = manager.TunnelUnknown
	}
	return entries, globalState
}

func (model *appModel) entry(name string) *tunnelEntry {
	for i := range model.entries {
		if model.entries[i].tunnel.Name == name {
			return &model.entries[i]
		}
	}
	return nil
}

// severity ranks how much a started tunnel needs attention.
func (entry *tunnelEntry) severity() int {
	switch {
	case entry.health == manager.TunnelHealthNoConnectionNetworkBlocked:
		return 5
	case entry.health == manager.TunnelHealthNoConnection:
		return 4
	case entry.health == manager.TunnelHealthWaitingForPeer:
		return 3
	case entry.conflictSuspected || entry.unstable:
		return 2
	case entry.health == manager.TunnelHealthConnected:
		return 1
	}
	return 0
}

// hero is the tunnel that the status screen is about: of the started ones the one that needs attention
// most, and the first by name among equals; failing that, one that is starting or stopping.
func (model *appModel) hero() *tunnelEntry {
	var hero *tunnelEntry
	for i := range model.entries {
		entry := &model.entries[i]
		if entry.state == manager.TunnelStarted && (hero == nil || entry.severity() > hero.severity()) {
			hero = entry
		}
	}
	if hero != nil {
		return hero
	}
	for i := range model.entries {
		if model.entries[i].active() {
			return &model.entries[i]
		}
	}
	return nil
}

// suggested is the tunnel offered for activation when none is active.
func (model *appModel) suggested() *tunnelEntry {
	if entry := model.entry(model.lastUsed); entry != nil {
		return entry
	}
	if len(model.entries) > 0 {
		return &model.entries[0]
	}
	return nil
}

func (model *appModel) canToggle() bool {
	return model.globalState == manager.TunnelStarted || model.globalState == manager.TunnelStopped
}

// Actions. They are called on the UI thread; owner is the window that dialogs belong to.

func (model *appModel) toggle(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil || !model.canToggle() {
		return
	}
	model.lastUsed = name
	tunnel := entry.tunnel
	go func() {
		oldState, err := tunnel.Toggle()
		if err == nil {
			return
		}
		model.synchronize(func() {
			switch oldState {
			case manager.TunnelUnknown:
				showErrorCustom(owner, l18n.Sprintf("Failed to determine tunnel state"), err.Error())
			case manager.TunnelStopped:
				showErrorCustom(owner, l18n.Sprintf("Failed to activate tunnel"), err.Error())
			case manager.TunnelStarted:
				showErrorCustom(owner, l18n.Sprintf("Failed to deactivate tunnel"), err.Error())
			}
		})
	}()
}

func (model *appModel) addTunnel(owner walk.Form) {
	if config := runEditDialog(owner, nil); config != nil {
		if _, err := manager.IPCClientNewTunnel(config); err != nil {
			showErrorCustom(owner, l18n.Sprintf("Unable to create tunnel"), err.Error())
		}
	}
}

func (model *appModel) editTunnel(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil {
		return
	}
	tunnel := entry.tunnel
	if config := runEditDialog(owner, &tunnel); config != nil {
		model.showDetailsOf(config.Name)
		go func() {
			priorState, err := tunnel.State()
			tunnel.Delete()
			tunnel.WaitForStop()
			tunnel, err2 := manager.IPCClientNewTunnel(config)
			if err == nil && err2 == nil && (priorState == manager.TunnelStarting || priorState == manager.TunnelStarted) {
				tunnel.Start()
			}
		}()
	}
}

// deleteTunnel asks for confirmation and removes a tunnel. It reports whether the user confirmed.
func (model *appModel) deleteTunnel(owner walk.Form, name string) bool {
	entry := model.entry(name)
	if entry == nil {
		return false
	}
	question := l18n.Sprintf("Are you sure you would like to delete tunnel ‘%s’?", name)
	if walk.DlgCmdNo == walk.MsgBox(owner, l18n.Sprintf("Delete tunnel ‘%s’", name), l18n.Sprintf("%s You cannot undo this action.", question), walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return false
	}
	tunnel := entry.tunnel
	go func() {
		if err := tunnel.Delete(); err != nil {
			model.synchronize(func() {
				showErrorCustom(owner, l18n.Sprintf("Unable to delete tunnel"), l18n.Sprintf("A tunnel was unable to be removed: %s", err.Error()))
			})
		}
	}()
	return true
}

func (model *appModel) importTunnels(owner walk.Form) {
	dlg := walk.FileDialog{
		Filter: l18n.Sprintf("Configuration Files (*.zip, *.conf)|*.zip;*.conf|All Files (*.*)|*.*"),
		Title:  l18n.Sprintf("Import tunnel(s) from file"),
	}
	if ok, _ := dlg.ShowOpenMultiple(owner); !ok {
		return
	}
	model.importFiles(owner, dlg.FilePaths)
}

func (model *appModel) importFiles(owner walk.Form, paths []string) {
	go func() {
		syncedMsgBox := func(title, message string, flags walk.MsgBoxStyle) {
			model.synchronize(func() {
				walk.MsgBox(owner, title, message, flags)
			})
		}
		type unparsedConfig struct {
			Name   string
			Config string
		}

		var (
			unparsedConfigs []unparsedConfig
			lastErr         error
		)

		for _, path := range paths {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".conf":
				textConfig, err := os.ReadFile(path)
				if err != nil {
					lastErr = err
					continue
				}
				unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), Config: string(textConfig)})
			case ".zip":
				// 1 .conf + 1 error .zip edge case?
				r, err := zip.OpenReader(path)
				if err != nil {
					lastErr = err
					continue
				}

				for _, f := range r.File {
					if strings.ToLower(filepath.Ext(f.Name)) != ".conf" {
						continue
					}

					rc, err := f.Open()
					if err != nil {
						lastErr = err
						continue
					}
					textConfig, err := io.ReadAll(rc)
					rc.Close()
					if err != nil {
						lastErr = err
						continue
					}
					unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(f.Name), filepath.Ext(f.Name)), Config: string(textConfig)})
				}

				r.Close()
			}
		}

		if lastErr != nil || unparsedConfigs == nil {
			if lastErr == nil {
				lastErr = errors.New(l18n.Sprintf("no configuration files were found"))
			}
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Could not import selected configuration: %v", lastErr), walk.MsgBoxIconWarning)
			return
		}

		existingTunnelList, err := manager.IPCClientTunnels()
		if err != nil {
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Could not enumerate existing tunnels: %v", err), walk.MsgBoxIconWarning)
			return
		}
		existingLowerTunnels := make(map[string]bool, len(existingTunnelList))
		for _, tunnel := range existingTunnelList {
			existingLowerTunnels[strings.ToLower(tunnel.Name)] = true
		}

		configCount := 0
		for _, unparsedConfig := range unparsedConfigs {
			if existingLowerTunnels[strings.ToLower(unparsedConfig.Name)] {
				lastErr = errors.New(l18n.Sprintf("Another tunnel already exists with the name ‘%s’", unparsedConfig.Name))
				continue
			}
			config, err := conf.FromWgQuickWithUnknownEncoding(unparsedConfig.Config, unparsedConfig.Name)
			if err != nil {
				lastErr = err
				continue
			}
			_, err = manager.IPCClientNewTunnel(config)
			if err != nil {
				lastErr = err
				continue
			}
			existingLowerTunnels[strings.ToLower(unparsedConfig.Name)] = true
			configCount++
		}

		m, n := configCount, len(unparsedConfigs)
		switch {
		case n == 1 && m != n:
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Unable to import configuration: %v", lastErr), walk.MsgBoxIconWarning)
		case n == 1 && m == n:
			// nothing
		case m == n:
			syncedMsgBox(l18n.Sprintf("Imported tunnels"), l18n.Sprintf("Imported %d tunnels", m), walk.MsgBoxIconInformation)
		case m != n:
			syncedMsgBox(l18n.Sprintf("Imported tunnels"), l18n.Sprintf("Imported %d of %d tunnels", m, n), walk.MsgBoxIconWarning)
		}
	}()
}

func (model *appModel) exportTunnels(owner walk.Form) {
	dlg := walk.FileDialog{
		Filter: l18n.Sprintf("Configuration ZIP Files (*.zip)|*.zip"),
		Title:  l18n.Sprintf("Export tunnels to zip"),
	}
	if ok, _ := dlg.ShowSave(owner); !ok {
		return
	}
	if !strings.HasSuffix(dlg.FilePath, ".zip") {
		dlg.FilePath += ".zip"
	}

	tunnels := make([]manager.Tunnel, len(model.entries))
	for i := range model.entries {
		tunnels[i] = model.entries[i].tunnel
	}
	writeFileWithOverwriteHandling(owner, dlg.FilePath, func(file *os.File) error {
		writer := zip.NewWriter(file)

		for _, tunnel := range tunnels {
			cfg, err := tunnel.StoredConfig()
			if err != nil {
				return fmt.Errorf("onExportTunnels: tunnel.StoredConfig failed: %w", err)
			}

			w, err := writer.Create(tunnel.Name + ".conf")
			if err != nil {
				return fmt.Errorf("onExportTunnels: writer.Create failed: %w", err)
			}

			if _, err := w.Write(([]byte)(cfg.ToWgQuick())); err != nil {
				return fmt.Errorf("onExportTunnels: cfg.ToWgQuick failed: %w", err)
			}
		}

		return writer.Close()
	})
}
