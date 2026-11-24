/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"image"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// A canvasView is a widget that draws a scene and lets its regions be operated with the mouse and
// the keyboard. What it shows is decided by its build function, which is called for every repaint.
type canvasView struct {
	walk.WidgetBase

	build func(s *scene, width, height float64)
	// onEscape, if set, is called when Escape is pressed while the view has the focus.
	onEscape func()

	last    *scene
	hot     string
	pressed string
	scroll  float64

	// focus is the id of the region that keys act on; its ring is drawn only after a key was used.
	focus         string
	focusVisible  bool
	trackingLeave bool

	// The last frame of shapes as BGRA pixels, kept so that only what changed is drawn again.
	frame                   []byte
	frameWidth, frameHeight int
	frameScale              float64
	frameShapes             []sceneShape

	bufferDC     win.HDC
	bufferBitmap win.HBITMAP
	bufferWidth  int
	bufferHeight int
	measureHDC   win.HDC
}

const (
	canvasViewWindowClass = "WireGuard UI - Canvas"
	canvasViewWheelStep   = 56
)

var (
	gdi32                 = windows.NewLazySystemDLL("gdi32.dll")
	procSetDIBitsToDevice = gdi32.NewProc("SetDIBitsToDevice")
)

func newCanvasView(parent walk.Container, build func(s *scene, width, height float64)) (*canvasView, error) {
	cv := &canvasView{build: build}
	if err := walk.InitWidget(cv, parent, canvasViewWindowClass, win.WS_VISIBLE|win.WS_TABSTOP, 0); err != nil {
		return nil, err
	}
	cv.MouseMove().Attach(func(x, y int, button walk.MouseButton) {
		cv.setHot(cv.hitID(x, y))
	})
	cv.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			cv.setHot(cv.hitID(x, y))
			cv.pressed = cv.hot
			if cv.focusVisible {
				cv.focusVisible = false
				cv.Invalidate()
			}
		}
	})
	cv.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button != walk.LeftButton {
			return
		}
		pressed := cv.pressed
		cv.pressed = ""
		if hit := cv.hitAt(x, y); hit != nil && hit.id == pressed && hit.action != nil {
			cv.focus = hit.id
			hit.action()
		}
	})
	cv.MouseWheel().Attach(func(x, y int, button walk.MouseButton) {
		cv.scrollBy(-float64(walk.MouseWheelEventDelta(button)) / 120 * canvasViewWheelStep)
	})
	cv.Disposing().Attach(func() {
		cv.releaseBuffer()
		if cv.measureHDC != 0 {
			win.DeleteDC(cv.measureHDC)
			cv.measureHDC = 0
		}
	})
	return cv, nil
}

func (*canvasView) CreateLayoutItem(ctx *walk.LayoutContext) walk.LayoutItem {
	return walk.NewGreedyLayoutItem()
}

func (cv *canvasView) releaseBuffer() {
	if cv.bufferDC != 0 {
		win.DeleteDC(cv.bufferDC)
		cv.bufferDC = 0
	}
	if cv.bufferBitmap != 0 {
		win.DeleteObject(win.HGDIOBJ(cv.bufferBitmap))
		cv.bufferBitmap = 0
	}
}

func (cv *canvasView) scale() float64 {
	return float64(cv.DPI()) / 96
}

func (cv *canvasView) hitAt(x, y int) *sceneHit {
	if cv.last == nil {
		return nil
	}
	scale := cv.scale()
	return cv.last.hitAt(float64(x)/scale, float64(y)/scale)
}

func (cv *canvasView) hitID(x, y int) string {
	if hit := cv.hitAt(x, y); hit != nil {
		return hit.id
	}
	return ""
}

func (cv *canvasView) setHot(id string) {
	if id == cv.hot {
		return
	}
	cv.hot = id
	if len(id) > 0 {
		cv.SetCursor(walk.CursorHand())
	} else {
		cv.SetCursor(walk.CursorArrow())
	}
	cv.Invalidate()
}

func (cv *canvasView) scrollBy(delta float64) {
	if cv.last == nil || cv.last.maxScroll <= 0 {
		return
	}
	scroll := cv.scroll + delta
	if scroll > cv.last.maxScroll {
		scroll = cv.last.maxScroll
	}
	if scroll < 0 {
		scroll = 0
	}
	if scroll != cv.scroll {
		cv.scroll = scroll
		cv.Invalidate()
	}
}

// reset shows the scrolling part of the view from its top again and forgets what was pointed at.
func (cv *canvasView) reset() {
	cv.scroll = 0
	cv.hot = ""
	cv.focus = ""
}

func (cv *canvasView) buildScene(width, height float64) *scene {
	dpi := cv.DPI()
	if cv.measureHDC == 0 {
		cv.measureHDC = win.CreateCompatibleDC(0)
	}
	for {
		s := &scene{hot: cv.hot, scroll: cv.scroll}
		s.measure = func(text string, font themeFont, width float64) float64 {
			return measureWrapped(cv.measureHDC, dpi, text, font, width)
		}
		s.lineWidth = func(text string, font themeFont) float64 {
			return measureLine(cv.measureHDC, dpi, text, font)
		}
		cv.build(s, width, height)
		if cv.scroll <= s.maxScroll || cv.scroll == 0 {
			if cv.focusVisible {
				s.focusRing(cv.focus)
			}
			return s
		}
		cv.scroll = s.maxScroll
		if cv.scroll < 0 {
			cv.scroll = 0
		}
	}
}

// contentHeight is the height in 1/96" units that the view would like to have at a width.
func (cv *canvasView) contentHeight(width float64) float64 {
	return cv.buildScene(width, 0).height
}

// Keyboard

// moveFocus moves the focus to the next or the previous region that can be operated. It reports
// false, and leaves the focus alone, at the ends.
func (cv *canvasView) moveFocus(forward bool) bool {
	if cv.last == nil {
		return false
	}
	ids := cv.last.focusOrder()
	if len(ids) == 0 {
		return false
	}
	index := -1
	for i, id := range ids {
		if id == cv.focus {
			index = i
			break
		}
	}
	switch {
	case index < 0 && forward:
		index = 0
	case index < 0:
		index = len(ids) - 1
	case !cv.focusVisible:
		// The first key only shows where the focus is.
	case forward && index+1 < len(ids):
		index++
	case !forward && index > 0:
		index--
	default:
		return false
	}
	cv.focus, cv.focusVisible = ids[index], true
	// Bring the region into view if it is in the scrolling part and outside of what is shown.
	if hit := cv.last.hitByID(cv.focus); hit != nil && hit.clipped {
		if above := hit.clip.y - hit.rect.y; above > 0 {
			cv.scroll -= above
		} else if below := hit.rect.y + hit.rect.h - (hit.clip.y + hit.clip.h); below > 0 {
			cv.scroll += below
		}
		if cv.scroll < 0 {
			cv.scroll = 0
		}
	}
	cv.Invalidate()
	return true
}

// canMoveFocus reports whether moveFocus would have somewhere to go.
func (cv *canvasView) canMoveFocus(forward bool) bool {
	if cv.last == nil {
		return false
	}
	ids := cv.last.focusOrder()
	if len(ids) == 0 {
		return false
	}
	if !cv.focusVisible {
		return true
	}
	for i, id := range ids {
		if id == cv.focus {
			return forward && i+1 < len(ids) || !forward && i > 0
		}
	}
	return true
}

func (cv *canvasView) activateFocus() {
	if cv.last == nil || !cv.focusVisible {
		return
	}
	if hit := cv.last.hitByID(cv.focus); hit != nil && hit.action != nil {
		hit.action()
	}
}

func shiftIsDown() bool {
	return win.GetKeyState(win.VK_SHIFT) < 0
}

func (cv *canvasView) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_PAINT:
		var ps win.PAINTSTRUCT
		hdc := win.BeginPaint(hwnd, &ps)
		if hdc == 0 {
			break
		}
		cv.paint(hdc)
		win.EndPaint(hwnd, &ps)
		return 0

	case win.WM_ERASEBKGND:
		return 1

	case win.WM_SIZE:
		cv.Invalidate()

	case win.WM_GETDLGCODE:
		// Tab is kept only while there is another region to go to, so that it still leaves the view at its ends.
		code := uintptr(win.DLGC_WANTARROWS)
		if lParam != 0 {
			if key := (*win.MSG)(unsafe.Pointer(lParam)); key.Message == win.WM_KEYDOWN {
				switch key.WParam {
				case win.VK_TAB:
					if cv.canMoveFocus(!shiftIsDown()) {
						code |= win.DLGC_WANTMESSAGE
					}
				case win.VK_RETURN, win.VK_SPACE:
					if cv.focusVisible {
						code |= win.DLGC_WANTMESSAGE
					}
				case win.VK_ESCAPE:
					if cv.onEscape != nil {
						code |= win.DLGC_WANTMESSAGE
					}
				}
			}
		}
		return code

	case win.WM_KEYDOWN:
		switch wParam {
		case win.VK_TAB:
			if cv.moveFocus(!shiftIsDown()) {
				return 0
			}
		case win.VK_DOWN, win.VK_RIGHT:
			cv.moveFocus(true)
			return 0
		case win.VK_UP, win.VK_LEFT:
			cv.moveFocus(false)
			return 0
		case win.VK_RETURN, win.VK_SPACE:
			if cv.focusVisible {
				cv.activateFocus()
				return 0
			}
		case win.VK_ESCAPE:
			if cv.onEscape != nil {
				cv.onEscape()
				return 0
			}
		}

	case win.WM_SETFOCUS:
		// Arriving by Tab shows the ring at once, on the first region or, going backwards, on the last.
		if win.GetKeyState(win.VK_TAB) < 0 && !cv.focusVisible {
			cv.focus = ""
			cv.moveFocus(!shiftIsDown())
		}

	case win.WM_KILLFOCUS:
		if cv.focusVisible {
			cv.focusVisible = false
			cv.Invalidate()
		}

	case win.WM_MOUSEMOVE:
		if !cv.trackingLeave {
			track := win.TRACKMOUSEEVENT{DwFlags: win.TME_LEAVE, HwndTrack: hwnd}
			track.CbSize = uint32(unsafe.Sizeof(track))
			cv.trackingLeave = win.TrackMouseEvent(&track)
		}

	case win.WM_MOUSELEAVE:
		cv.trackingLeave = false
		cv.pressed = ""
		cv.setHot("")
	}

	return cv.WidgetBase.WndProc(hwnd, msg, wParam, lParam)
}

// Painting

// updateFrame brings the kept frame of shapes up to date with the scene, drawing again only the
// part that differs from the last frame when the size is the same.
func (cv *canvasView) updateFrame(s *scene, width, height int, scale float64) {
	full := width != cv.frameWidth || height != cv.frameHeight || scale != cv.frameScale || len(s.shapes) != len(cv.frameShapes)
	dirty := image.Rect(0, 0, width, height)
	if full {
		cv.frame = make([]byte, width*height*4)
		cv.frameWidth, cv.frameHeight, cv.frameScale = width, height, scale
	} else {
		dirty = image.Rectangle{}
		for i := range s.shapes {
			if s.shapes[i] != cv.frameShapes[i] {
				dirty = dirty.Union(s.shapes[i].bounds(scale, width, height)).Union(cv.frameShapes[i].bounds(scale, width, height))
			}
		}
	}
	if !dirty.Empty() {
		s.rasterizeRegion(cv.frame, width, height, dirty, scale, themeBackdrop, true)
	}
	cv.frameShapes = s.shapes
}

func (cv *canvasView) paint(hdc win.HDC) {
	var client win.RECT
	if !win.GetClientRect(cv.Handle(), &client) || client.Right <= 0 || client.Bottom <= 0 {
		return
	}
	width, height := int(client.Right), int(client.Bottom)
	scale := cv.scale()
	s := cv.buildScene(float64(width)/scale, float64(height)/scale)
	cv.last = s
	cv.updateFrame(s, width, height, scale)

	// Shapes and texts are put together in a buffer first, so that the window never shows half of a frame.
	if cv.bufferDC == 0 || cv.bufferWidth != width || cv.bufferHeight != height {
		cv.releaseBuffer()
		cv.bufferDC = win.CreateCompatibleDC(hdc)
		cv.bufferBitmap = win.CreateCompatibleBitmap(hdc, int32(width), int32(height))
		if cv.bufferDC == 0 || cv.bufferBitmap == 0 {
			cv.releaseBuffer()
			return
		}
		win.SelectObject(cv.bufferDC, win.HGDIOBJ(cv.bufferBitmap))
		cv.bufferWidth, cv.bufferHeight = width, height
	}
	info := win.BITMAPINFOHEADER{
		BiWidth:       int32(width),
		BiHeight:      -int32(height), // Top-down
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: win.BI_RGB,
	}
	info.BiSize = uint32(unsafe.Sizeof(info))
	procSetDIBitsToDevice.Call(uintptr(cv.bufferDC), 0, 0, uintptr(width), uintptr(height), 0, 0, 0, uintptr(height),
		uintptr(unsafe.Pointer(&cv.frame[0])), uintptr(unsafe.Pointer(&info)), win.DIB_RGB_COLORS)
	s.drawTexts(cv.bufferDC, scale, cv.DPI())
	win.BitBlt(hdc, 0, 0, int32(width), int32(height), cv.bufferDC, 0, 0, win.SRCCOPY)
}
