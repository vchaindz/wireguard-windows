/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"image"
	"time"
	"unicode/utf16"
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
	// input, if set, receives what is typed while the view has the focus.
	input *textInput
	// swallowChar drops the character that follows a key which already operated a region, as Space does.
	swallowChar bool
	// highSurrogate is the first half of a character outside the basic plane, which arrives in two messages.
	highSurrogate uint16

	last    *scene
	hot     string
	pressed string
	scroll  float64
	// mouseX and mouseY are where the mouse was last seen over the view, in pixels.
	mouseX, mouseY int
	mouseIn        bool

	// focus is the id of the region that keys act on; its ring is drawn only after a key was used.
	focus         string
	focusVisible  bool
	trackingLeave bool

	// The last frame of shapes as BGRA pixels, kept so that only what changed is drawn again.
	frame                   []byte
	frameWidth, frameHeight int
	frameScale              float64
	frameShapes             []sceneShape
	// framePalette is the palette the kept frame was drawn with; another one makes the next frame a full one.
	framePalette *palette

	// anim keeps the animated values between frames; animating is set while the frame timer runs.
	anim      *animator
	animating bool

	bufferDC     win.HDC
	bufferBitmap win.HBITMAP
	bufferWidth  int
	bufferHeight int
	measureHDC   win.HDC
}

const (
	canvasViewWindowClass = "WireGuard UI - Canvas"
	canvasViewWheelStep   = 56
	// canvasViewFrameTimer is the id of the timer that repaints the view while something moves.
	canvasViewFrameTimer = 1
)

var (
	gdi32                 = windows.NewLazySystemDLL("gdi32.dll")
	procSetDIBitsToDevice = gdi32.NewProc("SetDIBitsToDevice")
)

// A textInput is a line of text that a view lets be typed into.
type textInput struct {
	// active reports whether the view shows the field now; typing is ignored while it does not.
	active  func() bool
	text    func() string
	setText func(text string)
}

// canvasViews are the views that exist, so that all of them can be drawn anew when the palette changes.
var canvasViews = make(map[*canvasView]bool)

// redrawCanvasViews repaints every view in full. Hidden views find out by themselves when they are shown again, as
// their kept frames remember the palette they were drawn with.
func redrawCanvasViews() {
	for cv := range canvasViews {
		cv.Invalidate()
	}
}

func newCanvasView(parent walk.Container, build func(s *scene, width, height float64)) (*canvasView, error) {
	cv := &canvasView{build: build}
	if err := walk.InitWidget(cv, parent, canvasViewWindowClass, win.WS_VISIBLE|win.WS_TABSTOP, 0); err != nil {
		return nil, err
	}
	canvasViews[cv] = true
	cv.MouseMove().Attach(func(x, y int, button walk.MouseButton) {
		moved := !cv.mouseIn || x != cv.mouseX || y != cv.mouseY
		cv.mouseX, cv.mouseY, cv.mouseIn = x, y, true
		hit := cv.hitAt(x, y)
		id := ""
		if hit != nil {
			id = hit.id
		}
		if id != cv.hot {
			cv.setHot(id)
		} else if moved && hit != nil && hit.tracksMouse {
			cv.Invalidate()
		}
	})
	cv.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			cv.setHot(cv.hitID(x, y))
			cv.pressed = cv.hot
			// Clicking a field that takes text means to type into it, which needs the keyboard focus.
			if hit := cv.hitAt(x, y); hit != nil && hit.textField && win.GetFocus() != cv.Handle() {
				cv.SetFocus()
			}
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
		delete(canvasViews, cv)
		cv.setAnimating(false)
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
	if hit := cv.hitByIDInLast(id); hit != nil && hit.action != nil {
		cv.SetCursor(walk.CursorHand())
	} else {
		cv.SetCursor(walk.CursorArrow())
	}
	cv.Invalidate()
}

func (cv *canvasView) hitByIDInLast(id string) *sceneHit {
	if cv.last == nil || len(id) == 0 {
		return nil
	}
	return cv.last.hitByID(id)
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

// buildScene builds a frame. Only frames that are painted take part in animation; anim is nil for frames that
// are built only to be measured.
func (cv *canvasView) buildScene(width, height float64, anim *animator) *scene {
	dpi := cv.DPI()
	if cv.measureHDC == 0 {
		cv.measureHDC = win.CreateCompatibleDC(0)
	}
	for {
		s := &scene{hot: cv.hot, scroll: cv.scroll, anim: anim, focus: cv.focus, focused: win.GetFocus() == cv.Handle()}
		if cv.mouseIn {
			scale := cv.scale()
			s.mouseX, s.mouseY, s.mouseIn = float64(cv.mouseX)/scale, float64(cv.mouseY)/scale, true
		}
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
	return cv.buildScene(width, 0, nil).height
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

// focusIsTextField reports whether the region that keys act on takes typed text, so that Space types a space.
func (cv *canvasView) focusIsTextField() bool {
	if cv.last == nil || cv.input == nil {
		return false
	}
	hit := cv.last.hitByID(cv.focus)
	return hit != nil && hit.textField
}

// inputActive reports whether typing goes into the text input of the view.
func (cv *canvasView) inputActive() bool {
	return cv.input != nil && cv.input.active()
}

// clearInput empties the text input and reports whether there was anything to clear.
func (cv *canvasView) clearInput() bool {
	if !cv.inputActive() || len(cv.input.text()) == 0 {
		return false
	}
	cv.input.setText("")
	cv.Invalidate()
	return true
}

// typeChar edits the text input with a character as WM_CHAR gives it, and reports whether it was taken.
func (cv *canvasView) typeChar(unit uint16) bool {
	if !cv.inputActive() {
		return false
	}
	text, changed, taken := editTyped(cv.input.text(), unit, &cv.highSurrogate)
	if changed {
		cv.input.setText(text)
		cv.Invalidate()
	}
	return taken
}

// editTyped applies a UTF-16 unit as WM_CHAR gives it to a text: Backspace deletes the last character, and other
// control characters, as Enter and Tab give, are left to the keys they belong to. A character outside the basic
// plane arrives in two halves, the first of which is kept in pending. It returns the text, whether it changed and
// whether the unit was taken.
func editTyped(text string, unit uint16, pending *uint16) (edited string, changed, taken bool) {
	switch {
	case unit == '\b':
		if len(text) == 0 {
			return text, false, true
		}
		runes := []rune(text)
		return string(runes[:len(runes)-1]), true, true
	case utf16.IsSurrogate(rune(unit)) && unit < 0xDC00:
		*pending = unit
		return text, false, true
	case utf16.IsSurrogate(rune(unit)):
		high := *pending
		*pending = 0
		if high == 0 {
			return text, false, true
		}
		return text + string(utf16.DecodeRune(rune(high), rune(unit))), true, true
	case unit < 0x20 || unit == 0x7F:
		return text, false, false
	}
	return text + string(rune(unit)), true, true
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

	case win.WM_TIMER:
		if wParam == canvasViewFrameTimer {
			// A hidden view gets no paint, so the timer would only spin; showing the view paints it again, which
			// starts the timer anew if something still moves.
			if !win.IsWindowVisible(hwnd) {
				cv.setAnimating(false)
			} else {
				cv.Invalidate()
			}
			return 0
		}

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
					if cv.onEscape != nil || cv.inputActive() && len(cv.input.text()) > 0 {
						code |= win.DLGC_WANTMESSAGE
					}
				}
			}
		}
		if cv.input != nil {
			// Without this, the dialog manager would take typed letters for mnemonics.
			code |= win.DLGC_WANTCHARS
		}
		return code

	case win.WM_CHAR:
		if cv.swallowChar {
			cv.swallowChar = false
			return 0
		}
		if cv.typeChar(uint16(wParam)) {
			return 0
		}

	case win.WM_KEYDOWN:
		cv.swallowChar = false
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
			if wParam == win.VK_SPACE && cv.focusIsTextField() {
				break
			}
			if cv.focusVisible {
				cv.activateFocus()
				cv.swallowChar = true
				return 0
			}
		case win.VK_ESCAPE:
			// Escape first empties what was typed, and only when there is nothing does what it did before.
			if cv.clearInput() {
				return 0
			}
			if cv.onEscape != nil {
				cv.onEscape()
				return 0
			}
		}

	case win.WM_SETFOCUS:
		// A caret is drawn only while the view has the focus.
		if cv.input != nil {
			cv.Invalidate()
		}
		// Arriving by Tab shows the ring at once, on the first region or, going backwards, on the last.
		if win.GetKeyState(win.VK_TAB) < 0 && !cv.focusVisible {
			cv.focus = ""
			cv.moveFocus(!shiftIsDown())
		}

	case win.WM_KILLFOCUS:
		if cv.input != nil {
			cv.Invalidate()
		}
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
		cv.mouseIn = false
		cv.setHot("")
	}

	return cv.WidgetBase.WndProc(hwnd, msg, wParam, lParam)
}

// Painting

// setAnimating starts or stops the timer that repaints the view about sixty times a second.
func (cv *canvasView) setAnimating(on bool) {
	if on == cv.animating || cv.Handle() == 0 {
		return
	}
	if on {
		cv.animating = win.SetTimer(cv.Handle(), canvasViewFrameTimer, uint32(animationFrame/time.Millisecond), 0) != 0
	} else {
		win.KillTimer(cv.Handle(), canvasViewFrameTimer)
		cv.animating = false
	}
}

// updateFrame brings the kept frame of shapes up to date with the scene, drawing again only the
// part that differs from the last frame when the size is the same. It returns the part it drew.
func (cv *canvasView) updateFrame(s *scene, width, height int, scale float64) image.Rectangle {
	full := width != cv.frameWidth || height != cv.frameHeight || scale != cv.frameScale || len(s.shapes) != len(cv.frameShapes) || cv.framePalette != theme
	dirty := image.Rect(0, 0, width, height)
	if full {
		cv.frame = make([]byte, width*height*4)
		cv.frameWidth, cv.frameHeight, cv.frameScale, cv.framePalette = width, height, scale, theme
	} else {
		dirty = image.Rectangle{}
		for i := range s.shapes {
			if s.shapes[i] != cv.frameShapes[i] {
				dirty = dirty.Union(s.shapes[i].bounds(scale, width, height)).Union(cv.frameShapes[i].bounds(scale, width, height))
			}
		}
	}
	if !dirty.Empty() {
		s.rasterizeRegion(cv.frame, width, height, dirty, scale, theme.backdrop, true)
	}
	cv.frameShapes = s.shapes
	return dirty
}

func (cv *canvasView) paint(hdc win.HDC) {
	var client win.RECT
	if !win.GetClientRect(cv.Handle(), &client) || client.Right <= 0 || client.Bottom <= 0 {
		return
	}
	width, height := int(client.Right), int(client.Bottom)
	scale := cv.scale()
	if cv.anim == nil {
		cv.anim = newAnimator()
	}
	cv.anim.beginFrame(time.Now(), animationsEnabled())
	s := cv.buildScene(float64(width)/scale, float64(height)/scale, cv.anim)
	cv.anim.endFrame()
	cv.setAnimating(cv.anim.moving)
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
