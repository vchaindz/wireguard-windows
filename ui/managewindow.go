/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sync"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

type screenKind int

const (
	screenStatus screenKind = iota
	screenDetails
	screenLog
	screenUpdate
)

type ManageTunnelsWindow struct {
	walk.FormBase

	model *appModel

	screen      screenKind
	detailsName string

	// mainView draws the status screen and the details screen.
	mainView     *canvasView
	logScreen    *walk.Composite
	logPage      *LogPage
	updateScreen *walk.Composite
	updatePage   *UpdatePage

	quitTicker      chan struct{}
	tunnelChangedCB *manager.TunnelChangeCallback
}

const (
	manageWindowWindowClass = "WireGuard UI - Manage Tunnels"
	raiseMsg                = win.WM_USER + 0x3510
	aboutWireGuardCmd       = 0x37
)

var taskbarButtonCreatedMsg uint32

var initedManageTunnels sync.Once

func NewManageTunnelsWindow() (*ManageTunnelsWindow, error) {
	initedManageTunnels.Do(func() {
		walk.AppendToWalkInit(func() {
			walk.MustRegisterWindowClass(manageWindowWindowClass)
			// The tray popup is created after the toolkit has run these functions, so its class is registered here.
			walk.MustRegisterWindowClass(trayPopupWindowClass)
			walk.MustRegisterWindowClass(canvasViewWindowClass)
			taskbarButtonCreatedMsg = win.RegisterWindowMessage(windows.StringToUTF16Ptr("TaskbarButtonCreated"))
		})
	})

	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	font, err := walk.NewFont("Segoe UI", 9, 0)
	if err != nil {
		return nil, err
	}

	mtw := new(ManageTunnelsWindow)
	mtw.SetName("WireGuard")

	err = walk.InitWindow(mtw, nil, manageWindowWindowClass, win.WS_OVERLAPPEDWINDOW, win.WS_EX_CONTROLPARENT)
	if err != nil {
		return nil, err
	}
	disposables.Add(mtw)
	win.ChangeWindowMessageFilterEx(mtw.Handle(), raiseMsg, win.MSGFLT_ALLOW, nil)
	mtw.SetPersistent(true)
	useDarkWindowFrame(mtw.Handle())

	if icon, err := loadLogoIcon(32); err == nil {
		mtw.SetIcon(icon)
	}
	mtw.SetTitle("WireGuard")
	mtw.SetFont(font)
	mtw.SetBackground(themeBrush(themeBackdrop))
	mtw.SetSize(walk.Size{540, 860})
	mtw.SetMinMaxSize(walk.Size{440, 560}, walk.Size{0, 0})
	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{})
	vlayout.SetSpacing(0)
	mtw.SetLayout(vlayout)
	mtw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		// "Close to tray" instead of exiting application
		*canceled = true
		if !noTrayAvailable {
			mtw.Hide()
		} else {
			win.ShowWindow(mtw.Handle(), win.SW_MINIMIZE)
		}
	})

	mtw.model = newAppModel(mtw.Synchronize)

	if mtw.mainView, err = newCanvasView(mtw, func(s *scene, width, height float64) {
		if mtw.screen == screenDetails {
			mtw.buildDetails(s, width, height)
		} else {
			mtw.buildStatus(s, width, height)
		}
	}); err != nil {
		return nil, err
	}

	if mtw.logScreen, err = mtw.newScreen(func() string { return l18n.Sprintf("Log") }); err != nil {
		return nil, err
	}
	logFilters, err := newCanvasView(mtw.logScreen, mtw.buildLogFilters)
	if err != nil {
		return nil, err
	}
	logFilters.SetMinMaxSize(walk.Size{0, logFiltersHeight}, walk.Size{0, logFiltersHeight})
	if mtw.logPage, err = NewLogPage(mtw.logScreen); err != nil {
		return nil, err
	}
	logFooter, err := newCanvasView(mtw.logScreen, func(s *scene, width, height float64) {
		buttonWidth := (width - 2*screenPadding - 8) / 2
		s.button("copy", screenPadding, 16, buttonWidth, 44, l18n.Sprintf("Copy"), buttonOutline, mtw.logPage.copySelectionOrAll)
		s.button("save", screenPadding+buttonWidth+8, 16, buttonWidth, 44, l18n.Sprintf("Save to file…"), buttonOutline, mtw.logPage.onSave)
	})
	if err != nil {
		return nil, err
	}
	logFooter.SetMinMaxSize(walk.Size{0, footerHeight}, walk.Size{0, footerHeight})
	mtw.logScreen.SetVisible(false)

	mtw.model.onChanged(func() {
		mtw.mainView.Invalidate()
		if mtw.screen == screenLog {
			logFilters.Invalidate()
		}
	})

	mtw.VisibleChanged().Attach(func() {
		if mtw.Visible() {
			mtw.model.refresh()
			win.SetForegroundWindow(mtw.Handle())
			win.BringWindowToTop(mtw.Handle())
			mtw.logPage.scrollToBottom()
		}
	})

	// While the window is shown, handshake times and traffic counters are kept up to date.
	mtw.quitTicker = make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if win.IsWindowVisible(mtw.Handle()) {
					mtw.model.refreshCounters()
				}
			case <-mtw.quitTicker:
				return
			}
		}
	}()

	for _, shortcut := range []struct {
		key     walk.Shortcut
		admin   bool
		handler func()
	}{
		{walk.Shortcut{walk.ModControl, walk.KeyO}, true, func() { mtw.model.importTunnels(mtw) }},
		{walk.Shortcut{walk.ModControl, walk.KeyN}, true, func() { mtw.model.addTunnel(mtw) }},
		{walk.Shortcut{walk.ModControl, walk.KeyL}, false, func() { mtw.showScreen(screenLog) }},
		{walk.Shortcut{0, walk.KeyEscape}, false, func() { mtw.showScreen(screenStatus) }},
	} {
		if shortcut.admin && !IsAdmin {
			continue
		}
		action := walk.NewAction()
		action.SetShortcut(shortcut.key)
		action.Triggered().Attach(shortcut.handler)
		mtw.ShortcutActions().Add(action)
	}

	mtw.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(mtw.onTunnelChange)
	globalState, _ := manager.IPCClientGlobalState()
	mtw.onTunnelChange(nil, manager.TunnelUnknown, globalState, nil)

	systemMenu := win.GetSystemMenu(mtw.Handle(), false)
	if systemMenu != 0 {
		win.InsertMenuItem(systemMenu, 0, true, &win.MENUITEMINFO{
			CbSize:     uint32(unsafe.Sizeof(win.MENUITEMINFO{})),
			FMask:      win.MIIM_ID | win.MIIM_STRING | win.MIIM_FTYPE,
			FType:      win.MIIM_STRING,
			DwTypeData: windows.StringToUTF16Ptr(l18n.Sprintf("&About WireGuard…")),
			WID:        uint32(aboutWireGuardCmd),
		})
		win.InsertMenuItem(systemMenu, 1, true, &win.MENUITEMINFO{
			CbSize: uint32(unsafe.Sizeof(win.MENUITEMINFO{})),
			FMask:  win.MIIM_TYPE,
			FType:  win.MFT_SEPARATOR,
		})
	}

	disposables.Spare()

	return mtw, nil
}

// newScreen creates a hidden container for a screen made of native controls, with the header bar on top.
func (mtw *ManageTunnelsWindow) newScreen(title func() string) (*walk.Composite, error) {
	screen, err := walk.NewComposite(mtw)
	if err != nil {
		return nil, err
	}
	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{})
	layout.SetSpacing(0)
	screen.SetLayout(layout)
	screen.SetBackground(themeBrush(themeBackdrop))
	header, err := newCanvasView(screen, func(s *scene, width, height float64) {
		s.header(width, title(), func() { mtw.showScreen(screenStatus) })
	})
	if err != nil {
		return nil, err
	}
	header.SetMinMaxSize(walk.Size{0, headerHeight + 1}, walk.Size{0, headerHeight + 1})
	return screen, nil
}

const logFiltersHeight = 50

// buildLogFilters draws the chips over the log: everything, warnings and errors only, and one per
// tunnel as far as they fit.
func (mtw *ManageTunnelsWindow) buildLogFilters(s *scene, width, height float64) {
	if mtw.logPage == nil {
		return
	}
	tunnel, warningsOnly := mtw.logPage.filter()
	set := func(tunnel string, warningsOnly bool) func() {
		return func() {
			mtw.logPage.setFilter(tunnel, warningsOnly)
		}
	}
	x, y := float64(screenPadding)-12, 10.0
	x += s.chip("all", x, y, l18n.Sprintf("All"), len(tunnel) == 0 && !warningsOnly, themeText, set("", false)) + 6
	x += s.chip("warnings", x, y, l18n.Sprintf("Warnings and errors"), warningsOnly, themeAmberSoft, set(tunnel, !warningsOnly)) + 6
	for i := range mtw.model.entries {
		name := mtw.model.entries[i].tunnel.Name
		if x+s.widthOf(name, fontSmall)+26 > width-16 {
			break
		}
		next := name
		if tunnel == name {
			next = ""
		}
		x += s.chip("tunnel:"+name, x, y, name, tunnel == name, themeText, set(next, warningsOnly)) + 6
	}
}

// showScreen switches what the window shows.
func (mtw *ManageTunnelsWindow) showScreen(screen screenKind) {
	if screen == screenUpdate && mtw.updateScreen == nil {
		screen = screenStatus
	}
	mtw.screen = screen
	if screen != screenDetails {
		mtw.detailsName = ""
		mtw.model.showDetailsOf("")
	}
	mtw.mainView.reset()
	mtw.SetSuspended(true)
	mtw.mainView.SetVisible(screen == screenStatus || screen == screenDetails)
	mtw.logScreen.SetVisible(screen == screenLog)
	if mtw.updateScreen != nil {
		mtw.updateScreen.SetVisible(screen == screenUpdate)
	}
	mtw.SetSuspended(false)
	mtw.mainView.Invalidate()
	if screen == screenLog {
		mtw.logPage.scrollToBottom()
	}
}

// showDetails switches to the screen about one tunnel.
func (mtw *ManageTunnelsWindow) showDetails(name string) {
	mtw.showScreen(screenDetails)
	mtw.detailsName = name
	mtw.model.showDetailsOf(name)
}

func (mtw *ManageTunnelsWindow) Dispose() {
	if mtw.tunnelChangedCB != nil {
		mtw.tunnelChangedCB.Unregister()
		mtw.tunnelChangedCB = nil
	}
	if mtw.quitTicker != nil {
		close(mtw.quitTicker)
		mtw.quitTicker = nil
	}
	if mtw.model != nil {
		mtw.model.dispose()
	}
	mtw.FormBase.Dispose()
}

func (mtw *ManageTunnelsWindow) updateProgressIndicator(globalState manager.TunnelState) {
	pi := mtw.ProgressIndicator()
	if pi == nil {
		return
	}
	switch globalState {
	case manager.TunnelStopping, manager.TunnelStarting:
		pi.SetState(walk.PIIndeterminate)
	default:
		pi.SetState(walk.PINoProgress)
	}
	if icon, err := iconForState(globalState, 16); err == nil {
		if globalState == manager.TunnelStopped {
			icon = nil
		}
		pi.SetOverlayIcon(icon, textForState(globalState, false))
	}
}

func (mtw *ManageTunnelsWindow) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	mtw.Synchronize(func() {
		mtw.updateProgressIndicator(globalState)

		if err != nil && mtw.Visible() {
			errMsg := err.Error()
			if len(errMsg) > 0 && errMsg[len(errMsg)-1] != '.' {
				errMsg += "."
			}
			showWarningCustom(mtw, l18n.Sprintf("Tunnel Error"), l18n.Sprintf("%s\n\nPlease consult the log for more information.", errMsg))
		}
	})
}

func (mtw *ManageTunnelsWindow) UpdateFound() {
	if mtw.updatePage != nil {
		return
	}
	if IsAdmin {
		mtw.SetTitle(l18n.Sprintf("%s (out of date)", mtw.Title()))
	}
	screen, err := mtw.newScreen(func() string { return l18n.Sprintf("An Update is Available!") })
	if err != nil {
		return
	}
	updatePage, err := NewUpdatePage(screen)
	if err != nil {
		screen.Dispose()
		return
	}
	screen.SetVisible(false)
	mtw.updateScreen, mtw.updatePage = screen, updatePage
	mtw.model.updateAvailable = true
	mtw.mainView.Invalidate()
}

// showUpdateOrStatus shows the update screen if there is an update, and the status screen otherwise.
func (mtw *ManageTunnelsWindow) showUpdateOrStatus() {
	if mtw.updateScreen != nil {
		mtw.showScreen(screenUpdate)
	} else {
		mtw.showScreen(screenStatus)
	}
}

func (mtw *ManageTunnelsWindow) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_QUERYENDSESSION:
		if lParam == win.ENDSESSION_CLOSEAPP {
			return win.TRUE
		}
	case win.WM_ENDSESSION:
		if lParam == win.ENDSESSION_CLOSEAPP && wParam == 1 {
			walk.App().Exit(198)
		}
	case win.WM_SYSCOMMAND:
		if wParam == aboutWireGuardCmd {
			onAbout(mtw)
			return 0
		}
	case raiseMsg:
		if mtw.mainView == nil || mtw.logScreen == nil {
			mtw.Synchronize(func() {
				mtw.SendMessage(msg, wParam, lParam)
			})
			return 0
		}
		if !mtw.Visible() || mtw.updateScreen != nil {
			mtw.showUpdateOrStatus()
		}
		raise(mtw.Handle())
		return 0
	case taskbarButtonCreatedMsg:
		ret := mtw.FormBase.WndProc(hwnd, msg, wParam, lParam)
		go func() {
			globalState, err := manager.IPCClientGlobalState()
			if err == nil {
				mtw.Synchronize(func() {
					mtw.updateProgressIndicator(globalState)
				})
			}
		}()
		return ret
	}

	return mtw.FormBase.WndProc(hwnd, msg, wParam, lParam)
}
