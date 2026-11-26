/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"time"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"

	"github.com/lxn/walk"
)

type trayTunnelHealth struct {
	health            manager.TunnelHealth
	conflictSuspected bool
	unstable          bool
}

type Tray struct {
	*walk.NotifyIcon

	mtw   *ManageTunnelsWindow
	popup *TrayPopup

	// Tunnels that were last seen active, to notify only on transitions
	activeTunnels map[string]bool
	// Last health reported for each started tunnel, to notify only on transitions
	tunnelHealth map[string]trayTunnelHealth

	tunnelChangedCB *manager.TunnelChangeCallback
	tunnelHealthCB  *manager.TunnelHealthCallback
	quitTicker      chan struct{}

	clicked func()
}

// trayRefreshInterval is how often the tooltip is brought up to date while the window is hidden, when nothing
// else asks the model for fresh counters.
const trayRefreshInterval = 10 * time.Second

func NewTray(mtw *ManageTunnelsWindow) (*Tray, error) {
	var err error

	tray := &Tray{
		mtw:           mtw,
		activeTunnels: make(map[string]bool),
		tunnelHealth:  make(map[string]trayTunnelHealth),
	}

	tray.NotifyIcon, err = walk.NewNotifyIcon(mtw)
	if err != nil {
		return nil, err
	}
	if tray.popup, err = NewTrayPopup(mtw, tray.onAbout); err != nil {
		tray.NotifyIcon.Dispose()
		return nil, err
	}

	return tray, tray.setup()
}

func (tray *Tray) setup() error {
	tray.clicked = tray.onManageTunnels

	tray.SetToolTip(l18n.Sprintf("WireGuard: Deactivated"))
	tray.SetVisible(true)
	if icon, err := stateIcon(trayOff, 16, tray.DPI()); err == nil {
		tray.SetIcon(icon)
	} else if icon, err := loadLogoIcon(16); err == nil {
		tray.SetIcon(icon)
	}

	tray.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			tray.clicked()
		}
	})
	// The context menu of the icon stays empty, so that a right click opens the popup instead.
	tray.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.RightButton {
			tray.popup.showAtCursor()
		}
	})
	tray.MessageClicked().Attach(func() {
		tray.clicked()
	})

	tray.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(tray.onTunnelChange)
	tray.tunnelHealthCB = manager.IPCClientRegisterTunnelHealth(tray.onTunnelHealth)
	tray.mtw.model.onChanged(tray.updateState)
	tray.updateState()

	// The time connected and the rates in the tooltip age while the window is hidden, as the model then only
	// hears of changes of state. A slow tick keeps them current for whoever points at the icon.
	tray.quitTicker = make(chan struct{})
	go func() {
		ticker := time.NewTicker(trayRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				tray.mtw.Synchronize(func() {
					if !tray.mtw.Visible() && tray.mtw.model.activeCount() > 0 {
						tray.mtw.model.refreshCounters()
					}
					tray.updateState()
				})
			case <-tray.quitTicker:
				return
			}
		}
	}()
	go func() {
		tunnels, err := manager.IPCClientTunnels()
		if err != nil {
			return
		}
		for _, tunnel := range tunnels {
			if state, err := tunnel.State(); err == nil && state == manager.TunnelStarted {
				name := tunnel.Name
				tray.mtw.Synchronize(func() {
					tray.activeTunnels[name] = true
				})
			}
		}
	}()

	return nil
}

func (tray *Tray) Dispose() error {
	if tray.tunnelChangedCB != nil {
		tray.tunnelChangedCB.Unregister()
		tray.tunnelChangedCB = nil
	}
	if tray.tunnelHealthCB != nil {
		tray.tunnelHealthCB.Unregister()
		tray.tunnelHealthCB = nil
	}
	if tray.quitTicker != nil {
		close(tray.quitTicker)
		tray.quitTicker = nil
	}
	if tray.popup != nil {
		tray.popup.Dispose()
		tray.popup = nil
	}
	return tray.NotifyIcon.Dispose()
}

func (tray *Tray) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	tray.mtw.Synchronize(func() {
		tray.updateState()
		if err == nil {
			wasActive := tray.activeTunnels[tunnel.Name]
			switch state {
			case manager.TunnelStarted:
				if !wasActive {
					icon, _ := stateIcon(trayConnected, balloonIconSize, tray.DPI())
					tray.ShowCustom(l18n.Sprintf("WireGuard Activated"), l18n.Sprintf("The %s tunnel has been activated.", tunnel.Name), icon)
				}
				tray.activeTunnels[tunnel.Name] = true

			case manager.TunnelStopped:
				if wasActive {
					icon, _ := stateIcon(trayOff, balloonIconSize, tray.DPI())
					tray.ShowCustom(l18n.Sprintf("WireGuard Deactivated"), l18n.Sprintf("The %s tunnel has been deactivated.", tunnel.Name), icon)
				}
				delete(tray.activeTunnels, tunnel.Name)
			}
		} else if !tray.mtw.Visible() {
			tray.ShowError(l18n.Sprintf("WireGuard Tunnel Error"), err.Error())
		}
		if state != manager.TunnelStarted {
			delete(tray.tunnelHealth, tunnel.Name)
		}
	})
}

func (tray *Tray) onTunnelHealth(tunnel *manager.Tunnel, health manager.TunnelHealth, conflictSuspected, unstable bool) {
	tray.mtw.Synchronize(func() {
		last := tray.tunnelHealth[tunnel.Name]
		tray.tunnelHealth[tunnel.Name] = trayTunnelHealth{health, conflictSuspected, unstable}
		if health.IsNoConnection() && !last.health.IsNoConnection() {
			switch health {
			case manager.TunnelHealthWaitingForPeer:
				tray.ShowWarning(l18n.Sprintf("WireGuard: No Connection"), l18n.Sprintf("The %s tunnel is active, but its peer does not answer. Its routes have not been applied, so the rest of your network is unaffected.", tunnel.Name))
			case manager.TunnelHealthNoConnectionNetworkBlocked:
				tray.ShowWarning(l18n.Sprintf("WireGuard: Network Cut Off"), l18n.Sprintf("The %s tunnel takes over all network traffic, but its peer does not answer. Your network is cut off until the peer answers or you deactivate the tunnel.", tunnel.Name))
			default:
				tray.ShowWarning(l18n.Sprintf("WireGuard: No Connection"), l18n.Sprintf("The %s tunnel is active, but its peer does not answer. Check the endpoint, the keys and your network.", tunnel.Name))
			}
		}
		if unstable && !last.unstable && !last.conflictSuspected {
			tray.ShowWarning(l18n.Sprintf("WireGuard: Unstable Connection"), l18n.Sprintf("The connection of the %s tunnel was lost and re-established. If this keeps happening, check your network, or whether another device uses the same configuration.", tunnel.Name))
		}
		if conflictSuspected && !last.conflictSuspected {
			tray.ShowWarning(l18n.Sprintf("WireGuard: Key Used Elsewhere"), l18n.Sprintf("Another device appears to be using the key of the %s tunnel, which breaks connections on both. Give each device its own key pair.", tunnel.Name))
		}
	})
}

// balloonIconSize is the size of the icon in notifications, which Windows shows larger than in the tray.
const balloonIconSize = 32

// updateState shows the worst state among the tunnels in the icon and tells about it in the tooltip.
func (tray *Tray) updateState() {
	model := tray.mtw.model
	state, _ := model.trayState()
	if icon, err := stateIcon(state, 16, tray.DPI()); err == nil {
		tray.SetIcon(icon)
	}
	tray.SetToolTip(model.trayToolTip(time.Now()))
}

func (tray *Tray) UpdateFound() {
	tray.clicked = tray.onManageTunnels

	showUpdateBalloon := func() {
		icon, _ := loadShieldIcon(128)
		tray.ShowCustom(l18n.Sprintf("WireGuard Update Available"), l18n.Sprintf("An update to WireGuard is now available. You are advised to update as soon as possible."), icon)
	}

	timeSinceStart := time.Now().Sub(startTime)
	if timeSinceStart < time.Second*3 {
		time.AfterFunc(time.Second*3-timeSinceStart, func() {
			tray.mtw.Synchronize(showUpdateBalloon)
		})
	} else {
		showUpdateBalloon()
	}
}

// onManageTunnels shows the main window: the update screen if there is an update, the status otherwise.
func (tray *Tray) onManageTunnels() {
	tray.mtw.showUpdateOrStatus()
	raise(tray.mtw.Handle())
}

func (tray *Tray) onAbout() {
	if tray.mtw.Visible() {
		onAbout(tray.mtw)
	} else {
		onAbout(nil)
	}
}
