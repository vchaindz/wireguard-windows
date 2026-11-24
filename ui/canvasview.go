/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// A canvasView is a widget that draws a scene and lets its regions be clicked. What it shows is
// decided by its build function, which is called for every repaint.
type canvasView struct {
	*walk.CustomWidget

	build func(s *scene, width, height float64)

	last    *scene
	hot     string
	pressed string
	scroll  float64

	bitmap     *walk.Bitmap
	signature  string
	measureHDC win.HDC
}

const canvasViewWheelStep = 56

func newCanvasView(parent walk.Container, build func(s *scene, width, height float64)) (*canvasView, error) {
	cv := &canvasView{build: build}
	var err error
	if cv.CustomWidget, err = walk.NewCustomWidgetPixels(parent, 0, cv.paint); err != nil {
		return nil, err
	}
	cv.SetPaintMode(walk.PaintBuffered)
	cv.SetInvalidatesOnResize(true)
	cv.MouseMove().Attach(func(x, y int, button walk.MouseButton) {
		cv.setHot(cv.hitID(x, y))
	})
	cv.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			cv.setHot(cv.hitID(x, y))
			cv.pressed = cv.hot
		}
	})
	cv.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button != walk.LeftButton {
			return
		}
		pressed := cv.pressed
		cv.pressed = ""
		if hit := cv.hitAt(x, y); hit != nil && hit.id == pressed && hit.action != nil {
			hit.action()
		}
	})
	cv.MouseWheel().Attach(func(x, y int, button walk.MouseButton) {
		if cv.last == nil || cv.last.maxScroll <= 0 {
			return
		}
		scroll := cv.scroll - float64(walk.MouseWheelEventDelta(button))/120*canvasViewWheelStep
		if scroll < 0 {
			scroll = 0
		}
		if scroll > cv.last.maxScroll {
			scroll = cv.last.maxScroll
		}
		if scroll != cv.scroll {
			cv.scroll = scroll
			cv.Invalidate()
		}
	})
	cv.Disposing().Attach(func() {
		if cv.bitmap != nil {
			cv.bitmap.Dispose()
			cv.bitmap = nil
		}
		if cv.measureHDC != 0 {
			win.DeleteDC(cv.measureHDC)
			cv.measureHDC = 0
		}
	})
	return cv, nil
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

// resetScroll shows the scrolling part of the view from its top again.
func (cv *canvasView) resetScroll() {
	cv.scroll = 0
	cv.hot = ""
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
		cv.build(s, width, height)
		if cv.scroll <= s.maxScroll || cv.scroll == 0 {
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

func (cv *canvasView) paint(canvas *walk.Canvas, updateBounds walk.Rectangle) error {
	bounds := cv.ClientBoundsPixels()
	if bounds.Width <= 0 || bounds.Height <= 0 {
		return nil
	}
	scale := cv.scale()
	s := cv.buildScene(float64(bounds.Width)/scale, float64(bounds.Height)/scale)
	cv.last = s

	signature := fmt.Sprint(bounds.Width, bounds.Height, scale, s.shapes)
	if cv.bitmap == nil || signature != cv.signature {
		bitmap, err := walk.NewBitmapFromImageForDPI(s.rasterize(bounds.Width, bounds.Height, scale, themeBackdrop), cv.DPI())
		if err != nil {
			return err
		}
		if cv.bitmap != nil {
			cv.bitmap.Dispose()
		}
		cv.bitmap, cv.signature = bitmap, signature
	}
	if err := canvas.DrawImagePixels(cv.bitmap, walk.Point{}); err != nil {
		return err
	}
	s.drawTexts(canvas.HDC(), scale, cv.DPI())
	return nil
}
