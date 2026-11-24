/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// The TrayPopup is the menu of the tray icon: a borderless window next to the icon that shows the
// connection state, lets tunnels be switched, and closes as soon as something else is clicked.
type TrayPopup struct {
	walk.FormBase

	mtw   *ManageTunnelsWindow
	view  *canvasView
	about func()
}

const (
	trayPopupWindowClass = "WireGuard UI - Tray Menu"
	trayPopupWidth       = 340
	trayPopupMaxRows     = 8
)

func NewTrayPopup(mtw *ManageTunnelsWindow, about func()) (*TrayPopup, error) {
	tp := &TrayPopup{mtw: mtw, about: about}
	if err := walk.InitWindow(tp, nil, trayPopupWindowClass, win.WS_POPUP, win.WS_EX_TOOLWINDOW|win.WS_EX_TOPMOST); err != nil {
		return nil, err
	}
	useRoundWindowCorners(tp.Handle())
	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{})
	layout.SetSpacing(0)
	tp.SetLayout(layout)

	var err error
	if tp.view, err = newCanvasView(tp, tp.build); err != nil {
		tp.Dispose()
		return nil, err
	}
	mtw.model.onChanged(func() {
		if win.IsWindowVisible(tp.Handle()) {
			tp.view.Invalidate()
		}
	})
	return tp, nil
}

func (tp *TrayPopup) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_ACTIVATE:
		if win.LOWORD(uint32(wParam)) == win.WA_INACTIVE {
			tp.hide()
		}
	case win.WM_CLOSE:
		// The popup lives as long as the tray icon; closing it only hides it.
		tp.hide()
		return 0
	}
	return tp.FormBase.WndProc(hwnd, msg, wParam, lParam)
}

func (tp *TrayPopup) hide() {
	win.ShowWindow(tp.Handle(), win.SW_HIDE)
}

// showAtCursor opens the popup above and to the left of the mouse, inside the work area of its monitor.
func (tp *TrayPopup) showAtCursor() {
	var cursor win.POINT
	if !win.GetCursorPos(&cursor) {
		return
	}
	// Moving the hidden popup to the cursor first makes it take on the DPI of that monitor.
	win.SetWindowPos(tp.Handle(), 0, cursor.X-1, cursor.Y-1, 1, 1, win.SWP_NOACTIVATE|win.SWP_NOZORDER)

	tp.mtw.model.refresh()
	tp.view.resetScroll()
	scale := tp.view.scale()
	width := int32(trayPopupWidth*scale + 0.5)
	height := int32(tp.view.contentHeight(trayPopupWidth)*scale + 0.5)
	x, y := cursor.X-width, cursor.Y-height-int32(8*scale)

	info := win.MONITORINFO{CbSize: uint32(unsafe.Sizeof(win.MONITORINFO{}))}
	if win.GetMonitorInfo(win.MonitorFromWindow(tp.Handle(), win.MONITOR_DEFAULTTONEAREST), &info) {
		margin := int32(8 * scale)
		work := info.RcWork
		if x+width > work.Right-margin {
			x = work.Right - margin - width
		}
		if x < work.Left+margin {
			x = work.Left + margin
		}
		if y+height > work.Bottom-margin {
			y = work.Bottom - margin - height
		}
		if y < work.Top+margin {
			y = work.Top + margin
		}
	}

	win.SetWindowPos(tp.Handle(), win.HWND_TOPMOST, x, y, width, height, win.SWP_SHOWWINDOW)
	tp.view.Invalidate()
	win.SetForegroundWindow(tp.Handle())
}

// build draws the popup. It reports the height it needs through the scene.
func (tp *TrayPopup) build(s *scene, width, height float64) {
	mtw, model := tp.mtw, tp.mtw.model
	act := func(action func()) func() {
		return func() {
			tp.hide()
			action()
		}
	}
	manage := act(func() {
		mtw.showUpdateOrStatus()
		raise(mtw.Handle())
	})

	// The state of the active tunnel
	hero := model.hero()
	look := lookFor(hero)
	const headerHeight = 76
	s.fill(0, 0, width, headerHeight, 0, look.background)
	s.fill(16, 33, 10, 10, 5, look.accent)
	textWidth := width - 38 - 16
	if hero != nil {
		textWidth -= 108
		name := hero.tunnel.Name
		subtitle := name
		if hero.config != nil && len(hero.config.Interface.Addresses) > 0 {
			subtitle = l18n.Sprintf("%s · %s", name, joinAddresses(hero.config.Interface.Addresses))
		}
		s.label(subtitle, fontSmall, themeTextDim, 38, 40, textWidth, 20, textLeft)
		if model.canToggle() {
			if s.hit("turn-off", width-16-96, 18, 96, 40, act(func() { model.toggle(mtw, name) })) {
				s.fill(width-16-96, 18, 96, 40, 8, themePanelHot)
			}
			s.stroke(width-16-96, 18, 96, 40, 8, 1, look.accent)
			s.label(l18n.Sprintf("Turn off"), fontBodyBold, look.accent, width-16-96+8, 18, 80, 40, textCenter)
		}
	} else {
		s.label(look.short, fontSmall, themeTextDim, 38, 40, textWidth, 20, textLeft)
	}
	s.label(look.title, fontHeading, themeText, 38, 15, textWidth, 26, textLeft)
	y := float64(headerHeight)

	if model.updateAvailable && IsAdmin {
		if s.hit("update", 6, y+6, width-12, 36, manage) {
			s.fill(6, y+6, width-12, 36, 6, themeAmberBg)
		}
		s.label(l18n.Sprintf("An Update is Available!"), fontBodyBold, themeAmberSoft, 16, y+6, width-32, 36, textLeft)
		y += 42
	}

	// The tunnels that can be switched to
	var others []*tunnelEntry
	for i := range model.entries {
		if hero == nil || model.entries[i].tunnel != hero.tunnel {
			others = append(others, &model.entries[i])
		}
	}
	if len(others) > 0 {
		caption := l18n.Sprintf("SWITCH TO")
		if hero == nil {
			caption = l18n.Sprintf("TUNNELS")
		}
		s.label(caption, fontCaps, themeTextDim, 16, y+10, width-32, 20, textLeft)
		y += 34

		const rowHeight = 40
		rows := len(others)
		if rows > trayPopupMaxRows {
			rows = trayPopupMaxRows
		}
		viewport := float64(rows * rowHeight)
		s.maxScroll = float64(len(others)*rowHeight) - viewport
		s.setClip(0, y, width, viewport)
		rowY := y - s.scroll
		for _, entry := range others {
			name := entry.tunnel.Name
			rowLook := lookFor(entry)
			status, statusColor := rowLook.short, rowLook.shortColor
			var action func()
			if model.canToggle() {
				action = act(func() { model.toggle(mtw, name) })
			}
			if s.hit("row:"+name, 6, rowY, width-12, rowHeight, action) && action != nil {
				s.fill(6, rowY, width-12, rowHeight, 6, themePanel)
				if entry.state == manager.TunnelStopped {
					status, statusColor = l18n.Sprintf("Activate"), themeText
				} else if entry.state == manager.TunnelStarted {
					status, statusColor = l18n.Sprintf("Deactivate"), themeText
				}
			}
			if entry.state == manager.TunnelStopped && status == rowLook.short {
				status = ""
			}
			s.glyph(rowLook.glyph, 16, rowY+14)
			s.label(name, fontBody, themeText, 38, rowY, width*0.5-38, rowHeight, textLeft)
			s.label(status, fontSmall, statusColor, width*0.5, rowY, width*0.5-16, rowHeight, textRight)
			rowY += rowHeight
		}
		s.clearClip()
		y += viewport + 6
	}

	// Everything else
	s.fill(0, y, width, 1, 0, themeLine)
	y += 1
	type item struct {
		id, label string
		style     buttonStyle
		action    func()
	}
	items := []item{{"manage", l18n.Sprintf("Manage tunnels"), buttonFlat, manage}}
	if IsAdmin {
		items = append(items, item{"import", l18n.Sprintf("Import…"), buttonFlat, act(func() {
			raise(mtw.Handle())
			model.importTunnels(mtw)
		})})
	}
	items = append(items, item{"about", l18n.Sprintf("About"), buttonFlat, act(tp.about)})
	if IsAdmin {
		items = append(items, item{"exit", l18n.Sprintf("Exit"), buttonFlat, act(onQuit)})
	}
	const itemHeight, gap = 40, 6
	columnWidth := (width - 20 - gap) / 2
	for i, it := range items {
		column, row := float64(i%2), float64(i/2)
		itemWidth := columnWidth
		if i == len(items)-1 && i%2 == 0 {
			itemWidth = width - 20
		}
		s.button(it.id, 10+column*(columnWidth+gap), y+10+row*(itemHeight+gap), itemWidth, itemHeight, it.label, it.style, it.action)
	}
	rowsOfItems := float64((len(items) + 1) / 2)
	y += 10 + rowsOfItems*(itemHeight+gap) - gap + 10

	s.height = y
	s.stroke(0, 0, width, y, 0, 1, themeBorder)
}
