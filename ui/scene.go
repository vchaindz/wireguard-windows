/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"image"
	"math"

	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// Text formats, as DrawText takes them.
const (
	textLeft     = 0x0
	textCenter   = 0x1
	textRight    = 0x2
	textVCenter  = 0x4
	textWrap     = 0x10 | 0x2000 // Break between words, and inside words that are longer than a line
	textOneLine  = 0x20
	textCalcRect = 0x400
	textNoPrefix = 0x800
	textEllipsis = 0x8000
)

// A scene is one frame of a custom-drawn view: anti-aliased shapes, texts on top of them, and the
// regions that react to the mouse. All coordinates are in 1/96" units; painting scales them.

type sceneRect struct {
	x, y, w, h float64
}

func (r sceneRect) contains(x, y float64) bool {
	return x >= r.x && y >= r.y && x < r.x+r.w && y < r.y+r.h
}

type shapeKind int

const (
	shapeFill   shapeKind = iota // filled rounded rectangle
	shapeStroke                  // outline of a rounded rectangle, drawn inside its bounds
	shapeLine                    // polyline with round caps and joins
	shapePoly                    // filled convex polygon
)

type sceneShape struct {
	kind    shapeKind
	rect    sceneRect
	radius  float64
	width   float64
	dash    float64
	points  [16][2]float64
	nPoints int
	color   rgb
	clip    sceneRect
	clipped bool
}

type sceneText struct {
	text    string
	font    themeFont
	color   rgb
	rect    sceneRect
	format  uint32
	clip    sceneRect
	clipped bool
}

type sceneHit struct {
	id      string
	rect    sceneRect
	action  func()
	clip    sceneRect
	clipped bool
}

type scene struct {
	shapes []sceneShape
	texts  []sceneText
	hits   []sceneHit

	clip    sceneRect
	clipped bool

	// hot is the id of the region under the mouse, set before the scene is built.
	hot string
	// scroll is how far the scrolling part of the view is scrolled, and maxScroll how far it can be.
	scroll, maxScroll float64
	// height is the height the content would like to have, for views that size themselves.
	height float64

	measure func(text string, font themeFont, width float64) float64
}

func (s *scene) setClip(x, y, w, h float64) {
	s.clip, s.clipped = sceneRect{x, y, w, h}, true
}

func (s *scene) clearClip() {
	s.clipped = false
}

func (s *scene) add(shape sceneShape) {
	shape.clip, shape.clipped = s.clip, s.clipped
	s.shapes = append(s.shapes, shape)
}

func (s *scene) fill(x, y, w, h, radius float64, color rgb) {
	s.add(sceneShape{kind: shapeFill, rect: sceneRect{x, y, w, h}, radius: radius, color: color})
}

func (s *scene) stroke(x, y, w, h, radius, width float64, color rgb) {
	s.add(sceneShape{kind: shapeStroke, rect: sceneRect{x, y, w, h}, radius: radius, width: width, color: color})
}

// dashedRing is a circle outline broken into dashes of the given length.
func (s *scene) dashedRing(x, y, size, width, dash float64, color rgb) {
	s.add(sceneShape{kind: shapeStroke, rect: sceneRect{x, y, size, size}, radius: size / 2, width: width, dash: dash, color: color})
}

func (s *scene) pointsShape(kind shapeKind, width float64, color rgb, points []float64) {
	shape := sceneShape{kind: kind, width: width, color: color}
	for i := 0; i+1 < len(points) && shape.nPoints < len(shape.points); i += 2 {
		shape.points[shape.nPoints] = [2]float64{points[i], points[i+1]}
		shape.nPoints++
	}
	s.add(shape)
}

func (s *scene) line(width float64, color rgb, points ...float64) {
	s.pointsShape(shapeLine, width, color, points)
}

func (s *scene) poly(color rgb, points ...float64) {
	s.pointsShape(shapePoly, 0, color, points)
}

func (s *scene) text(text string, font themeFont, color rgb, x, y, w, h float64, format uint32) {
	if len(text) == 0 || w <= 0 || h <= 0 {
		return
	}
	s.texts = append(s.texts, sceneText{text, font, color, sceneRect{x, y, w, h}, format | textNoPrefix, s.clip, s.clipped})
}

// label is a single line of text, vertically centered and cut off with an ellipsis.
func (s *scene) label(text string, font themeFont, color rgb, x, y, w, h float64, align uint32) {
	s.text(text, font, color, x, y, w, h, align|textVCenter|textOneLine|textEllipsis)
}

// wrappedHeight is the height that text needs when it is broken into lines of the given width.
func (s *scene) wrappedHeight(text string, font themeFont, width float64) float64 {
	if s.measure == nil || len(text) == 0 {
		return 20
	}
	return s.measure(text, font, width)
}

// hit makes a region react to the mouse and reports whether the mouse is over it.
func (s *scene) hit(id string, x, y, w, h float64, action func()) bool {
	s.hits = append(s.hits, sceneHit{id, sceneRect{x, y, w, h}, action, s.clip, s.clipped})
	return s.hot == id
}

func (s *scene) hitAt(x, y float64) *sceneHit {
	for i := len(s.hits) - 1; i >= 0; i-- {
		hit := &s.hits[i]
		if hit.rect.contains(x, y) && (!hit.clipped || hit.clip.contains(x, y)) {
			return hit
		}
	}
	return nil
}

// Painting

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// roundRectDistance is the signed distance of a point to a rounded rectangle given by its center,
// its half size and its corner radius. It is negative inside.
func roundRectDistance(px, py, cx, cy, hw, hh, radius float64) float64 {
	qx := math.Abs(px-cx) - (hw - radius)
	qy := math.Abs(py-cy) - (hh - radius)
	return math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - radius
}

func segmentDistance(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := 0.0
	if length := dx*dx + dy*dy; length > 0 {
		t = clamp01(((px-ax)*dx + (py-ay)*dy) / length)
	}
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// coverage is how much of the pixel at (px, py) the shape covers, with all lengths in pixels.
func (shape *sceneShape) coverage(px, py, scale float64) float64 {
	switch shape.kind {
	case shapeFill, shapeStroke:
		hw, hh := shape.rect.w*scale/2, shape.rect.h*scale/2
		cx, cy := shape.rect.x*scale+hw, shape.rect.y*scale+hh
		radius := math.Min(shape.radius*scale, math.Min(hw, hh))
		distance := roundRectDistance(px, py, cx, cy, hw, hh, radius)
		if shape.kind == shapeFill {
			return clamp01(0.5 - distance)
		}
		if shape.dash > 0 {
			along := (math.Atan2(py-cy, px-cx) + math.Pi) * radius
			if math.Mod(along, shape.dash*scale*2) > shape.dash*scale {
				return 0
			}
		}
		return clamp01(0.5-distance) * clamp01(0.5+distance+shape.width*scale)
	case shapeLine:
		distance := math.MaxFloat64
		for i := 0; i+1 < shape.nPoints; i++ {
			a, b := shape.points[i], shape.points[i+1]
			distance = math.Min(distance, segmentDistance(px, py, a[0]*scale, a[1]*scale, b[0]*scale, b[1]*scale))
		}
		return clamp01(0.5 - (distance - shape.width*scale/2))
	case shapePoly:
		area := 0.0
		for i := 0; i < shape.nPoints; i++ {
			a, b := shape.points[i], shape.points[(i+1)%shape.nPoints]
			area += a[0]*b[1] - b[0]*a[1]
		}
		sign := 1.0
		if area < 0 {
			sign = -1
		}
		distance := -math.MaxFloat64
		for i := 0; i < shape.nPoints; i++ {
			a, b := shape.points[i], shape.points[(i+1)%shape.nPoints]
			ex, ey := (b[0]-a[0])*scale, (b[1]-a[1])*scale
			length := math.Hypot(ex, ey)
			if length == 0 {
				continue
			}
			distance = math.Max(distance, sign*((px-a[0]*scale)*ey-(py-a[1]*scale)*ex)/length)
		}
		return clamp01(0.5 - distance)
	}
	return 0
}

// bounds is the rectangle of pixels that the shape can touch.
func (shape *sceneShape) bounds(scale float64, width, height int) image.Rectangle {
	rect := shape.rect
	if shape.kind == shapeLine || shape.kind == shapePoly {
		minX, minY, maxX, maxY := math.MaxFloat64, math.MaxFloat64, -math.MaxFloat64, -math.MaxFloat64
		for i := 0; i < shape.nPoints; i++ {
			minX, maxX = math.Min(minX, shape.points[i][0]), math.Max(maxX, shape.points[i][0])
			minY, maxY = math.Min(minY, shape.points[i][1]), math.Max(maxY, shape.points[i][1])
		}
		pad := shape.width/2 + 1
		rect = sceneRect{minX - pad, minY - pad, maxX - minX + 2*pad, maxY - minY + 2*pad}
	}
	bounds := image.Rect(int(math.Floor(rect.x*scale))-1, int(math.Floor(rect.y*scale))-1, int(math.Ceil((rect.x+rect.w)*scale))+1, int(math.Ceil((rect.y+rect.h)*scale))+1)
	if shape.clipped {
		clip := shape.clip
		bounds = bounds.Intersect(image.Rect(int(math.Round(clip.x*scale)), int(math.Round(clip.y*scale)), int(math.Round((clip.x+clip.w)*scale)), int(math.Round((clip.y+clip.h)*scale))))
	}
	return bounds.Intersect(image.Rect(0, 0, width, height))
}

// rasterize draws the shapes of the scene into an opaque image of the given size in pixels.
func (s *scene) rasterize(width, height int, scale float64, background rgb) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = byte(background>>16), byte(background>>8), byte(background), 0xff
	}
	for i := range s.shapes {
		shape := &s.shapes[i]
		bounds := shape.bounds(scale, width, height)
		r, g, b := float64(byte(shape.color>>16)), float64(byte(shape.color>>8)), float64(byte(shape.color))
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			row := img.Pix[y*img.Stride:]
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				cover := shape.coverage(float64(x)+0.5, float64(y)+0.5, scale)
				if cover <= 0 {
					continue
				}
				pix := row[x*4 : x*4+3 : x*4+3]
				pix[0] = byte(float64(pix[0]) + (r-float64(pix[0]))*cover + 0.5)
				pix[1] = byte(float64(pix[1]) + (g-float64(pix[1]))*cover + 0.5)
				pix[2] = byte(float64(pix[2]) + (b-float64(pix[2]))*cover + 0.5)
			}
		}
	}
	return img
}

// drawTexts draws the texts of the scene onto a device context that already shows the shapes.
func (s *scene) drawTexts(hdc win.HDC, scale float64, dpi int) {
	px := func(v float64) int32 { return int32(math.Round(v * scale)) }
	win.SetBkMode(hdc, win.TRANSPARENT)
	for i := range s.texts {
		text := &s.texts[i]
		saved := win.SaveDC(hdc)
		if text.clipped {
			win.IntersectClipRect(hdc, px(text.clip.x), px(text.clip.y), px(text.clip.x+text.clip.w), px(text.clip.y+text.clip.h))
		}
		win.SelectObject(hdc, win.HGDIOBJ(text.font.handle(dpi)))
		win.SetTextColor(hdc, win.COLORREF(text.color.walk()))
		rect := win.RECT{Left: px(text.rect.x), Top: px(text.rect.y), Right: px(text.rect.x + text.rect.w), Bottom: px(text.rect.y + text.rect.h)}
		win.DrawTextEx(hdc, windows.StringToUTF16Ptr(text.text), -1, &rect, text.format, nil)
		win.RestoreDC(hdc, saved)
	}
}

// measureWrapped returns the height in 1/96" units that text needs when wrapped to a width.
func measureWrapped(hdc win.HDC, dpi int, text string, font themeFont, width float64) float64 {
	scale := float64(dpi) / 96
	saved := win.SaveDC(hdc)
	win.SelectObject(hdc, win.HGDIOBJ(font.handle(dpi)))
	rect := win.RECT{Right: int32(width*scale + 0.5)}
	win.DrawTextEx(hdc, windows.StringToUTF16Ptr(text), -1, &rect, textWrap|textCalcRect|textNoPrefix, nil)
	win.RestoreDC(hdc, saved)
	return math.Ceil(float64(rect.Bottom) / scale)
}
