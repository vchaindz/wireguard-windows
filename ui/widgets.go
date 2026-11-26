/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import "math"

// Building blocks that the screens are drawn from.

type buttonStyle int

const (
	buttonGreen buttonStyle = iota
	buttonAmber
	buttonRed
	buttonOutline
	buttonDanger
	buttonDisabled
	buttonFlat
)

func (s *scene) button(id string, x, y, w, h float64, label string, style buttonStyle, action func()) {
	// How far the hover look has faded in. Every style draws the same shapes hovered or not, so that a
	// fading button redraws only itself.
	hover := 0.0
	if style != buttonDisabled {
		hover = s.hoverAmount(id, s.hit(id, x, y, w, h, action))
	}
	pick := func(normal, hovered rgb) rgb {
		return mix(normal, hovered, hover)
	}
	font, ink := fontBodyBold, theme.text
	switch style {
	case buttonGreen:
		s.fill(x, y, w, h, 8, pick(theme.green, theme.greenHot))
		ink = theme.greenInk
	case buttonAmber:
		s.fill(x, y, w, h, 8, pick(theme.amber, theme.amberHot))
		ink = theme.amberInk
	case buttonRed:
		s.fill(x, y, w, h, 8, pick(theme.red, theme.redHot))
		ink = theme.redInk
	case buttonOutline, buttonDanger:
		s.fillFaded(x, y, w, h, 8, theme.panelHot, hover)
		s.stroke(x, y, w, h, 8, 1, theme.border)
		font = fontBody
		if style == buttonDanger {
			ink = theme.redSoft
		}
	case buttonDisabled:
		s.fill(x, y, w, h, 8, theme.panel)
		ink = theme.muted
	case buttonFlat:
		s.fill(x, y, w, h, 6, pick(theme.panel, theme.panelHot))
		font = fontBody
	}
	s.label(label, font, ink, x+8, y, w-16, h, textCenter)
}

const (
	toggleWidth  = 44
	toggleHeight = 24
)

// toggle draws a switch. Its clickable region is larger than what is drawn. When it is switched, the knob slides
// across and grows a little while the outline of the track fades into its fill.
func (s *scene) toggle(id string, x, y float64, on, enabled bool, action func()) {
	if enabled {
		s.hit(id, x-8, y-10, toggleWidth+16, toggleHeight+20, action)
	}
	target := 0.0
	if on {
		target = 1
	}
	t := s.animate("toggle:"+id, target)
	color := theme.green
	if !enabled {
		color = theme.muted
	}
	s.strokeFaded(x, y, toggleWidth, toggleHeight, toggleHeight/2, 1, theme.muted, 1-t)
	s.fillFaded(x, y, toggleWidth, toggleHeight, toggleHeight/2, color, t)
	knob := lerp(16, 18, t)
	knobX, knobY := lerp(x+4, x+toggleWidth-21, t), y+(toggleHeight-knob)/2
	s.fill(knobX, knobY, knob, knob, knob/2, mix(theme.textDim, theme.greenInk, t))
}

// path draws a polyline given in the coordinates of a 44x44 icon box, scaled to size.
func (s *scene) path(x, y, size, width float64, color rgb, points ...float64) {
	scaled := make([]float64, len(points))
	for i := range points {
		origin := x
		if i%2 == 1 {
			origin = y
		}
		scaled[i] = origin + points[i]*size/44
	}
	s.line(width*size/44, color, scaled...)
}

type iconKind int

const (
	iconShield iconKind = iota
	iconShieldCheck
	iconShieldCross
	iconClock
)

func (s *scene) icon(kind iconKind, x, y, size float64, color rgb) {
	const width = 2.5
	if kind == iconClock {
		s.stroke(x+size*7/44, y+size*7/44, size*30/44, size*30/44, size*15/44, width*size/44, color)
		s.path(x, y, size, width, color, 22, 13, 22, 22, 28, 26)
		return
	}
	s.path(x, y, size, width, color,
		22, 4, 36, 9, 36, 20, 34.94, 26.36, 32, 31.88, 27.56, 36.45, 22, 40,
		16.44, 36.45, 12, 31.88, 9.06, 26.36, 8, 20, 8, 9, 22, 4)
	switch kind {
	case iconShieldCheck:
		s.path(x, y, size, width, color, 15, 22, 20, 27, 29, 17)
	case iconShieldCross:
		s.path(x, y, size, width, color, 16.5, 16.5, 27.5, 27.5)
		s.path(x, y, size, width, color, 27.5, 16.5, 16.5, 27.5)
	}
}

// warningSign draws a triangle with an exclamation mark.
func (s *scene) warningSign(x, y, size float64, color, ink rgb) {
	s.poly(color, x+size/2, y+size*0.05, x+size*0.98, y+size*0.92, x+size*0.02, y+size*0.92)
	if size >= 14 {
		s.line(size*0.1, ink, x+size/2, y+size*0.4, x+size/2, y+size*0.62)
		s.fill(x+size/2-size*0.06, y+size*0.72, size*0.12, size*0.12, size*0.06, ink)
	}
}

type glyphKind int

const (
	glyphOff glyphKind = iota
	glyphOn
	glyphBusy
	glyphWarning
	glyphAlert
)

// glyph draws the small status mark in front of a tunnel name, centered in a 12x12 box.
func (s *scene) glyph(kind glyphKind, x, y float64) {
	switch kind {
	case glyphOn:
		s.fill(x+1, y+1, 10, 10, 5, theme.green)
	case glyphBusy:
		s.fill(x+1, y+1, 10, 10, 5, theme.textDim)
	case glyphWarning:
		s.warningSign(x, y, 12, theme.amber, theme.amberInk)
	case glyphAlert:
		s.warningSign(x, y, 12, theme.red, theme.redInk)
	default:
		s.stroke(x+1, y+1, 10, 10, 5, 2, theme.muted)
	}
}

type noticeKind int

const (
	noticeAmber noticeKind = iota
	noticeRed
)

// notice draws a message box with wrapped text and returns its height.
func (s *scene) notice(x, y, w float64, kind noticeKind, title, text string) float64 {
	bg, border, ink, heading, sign, signInk := theme.amberBg, theme.amberBorder, theme.amberText, theme.amberSoft, theme.amber, theme.amberBg
	if kind == noticeRed {
		bg, border, ink, heading, sign, signInk = theme.redBg, theme.redBorder, theme.redText, theme.redSoft, theme.red, theme.redBg
	}
	const textX = 42
	textWidth := w - textX - 14
	textHeight := s.wrappedHeight(text, fontBody, textWidth)
	height := textHeight + 24
	if len(title) > 0 {
		height += 22
	}
	s.fill(x, y, w, height, 8, bg)
	s.stroke(x, y, w, height, 8, 1, border)
	s.warningSign(x+14, y+13, 16, sign, signInk)
	textY := y + 12
	if len(title) > 0 {
		s.label(title, fontBodyBold, heading, x+textX, textY, textWidth, 20, textLeft)
		textY += 22
	}
	s.text(text, fontBody, ink, x+textX, textY, textWidth, textHeight, textWrap)
	return height
}

// backButton draws the arrow that leads back to the previous screen, in the top left corner.
func (s *scene) backButton(action func()) {
	s.fillFaded(4, 4, 44, 44, 6, theme.panelHot, s.hoverAmount("back", s.hit("back", 4, 4, 44, 44, action)))
	s.line(1.8, theme.text, 29, 19, 23, 26, 29, 33)
}

// chip draws a pill that filters a list and returns its width. A selected chip is filled.
func (s *scene) chip(id string, x, y float64, label string, selected bool, accent rgb, action func()) float64 {
	const height = 30
	width := s.widthOf(label, fontSmall) + 26
	hover := s.hoverAmount(id, s.hit(id, x, y, width, height, action))
	// Selecting a chip fills it with its accent; the outline fades out as the fill comes in.
	target := 0.0
	if selected {
		target = 1
	}
	chosen := s.animate("chip:"+id, target)
	s.fillFaded(x, y, width, height, height/2, mix(theme.panelHot, accent, chosen), math.Max(hover, chosen))
	s.strokeFaded(x, y, width, height, height/2, 1, theme.border, 1-chosen)
	ink := accent
	if chosen >= 0.5 {
		ink = theme.backdrop
	}
	s.label(label, fontSmall, ink, x, y, width, height, textCenter)
	return width
}

// star draws a filled five-pointed star of a size, centered on a point. As shapes can only be convex, it is made of
// the pentagon in its middle and a triangle for each point.
func (s *scene) star(cx, cy, size float64, color rgb) {
	outer, inner := size/2, size/2*0.42
	point := func(i int, radius float64) (float64, float64) {
		angle := -math.Pi/2 + float64(i)*math.Pi/5
		return cx + radius*math.Cos(angle), cy + radius*math.Sin(angle)
	}
	var pentagon []float64
	for i := 0; i < 5; i++ {
		tipX, tipY := point(2*i, outer)
		leftX, leftY := point(2*i-1, inner)
		rightX, rightY := point(2*i+1, inner)
		s.poly(color, leftX, leftY, tipX, tipY, rightX, rightY)
		pentagon = append(pentagon, rightX, rightY)
	}
	s.poly(color, pentagon...)
}

// tunnelMark draws the color of a tunnel as a short upright bar, if it has a color.
func (s *scene) tunnelMark(entry *tunnelEntry, x, y, height float64) {
	if color, ok := tunnelColor(entry.settings.Color); ok {
		s.fill(x, y, 4, height, 2, color)
	}
}

// textField draws a field that text is typed into, with a placeholder while it is empty and a caret while it has
// the focus, and a button that empties it while it is not. It returns its height.
func (s *scene) textField(id string, x, y, w float64, text, placeholder string, action, clear func()) float64 {
	const height, pad = 36, 12
	s.hits = append(s.hits, sceneHit{id: id, rect: sceneRect{x, y, w, height}, action: action, clip: s.clip, clipped: s.clipped, textField: true})
	hover := s.hoverAmount(id, s.hot == id)
	active := s.focused && (s.focus == id || len(text) > 0)
	s.fill(x, y, w, height, 8, mix(theme.panel, theme.panelHot, hover))
	border := theme.border
	if active {
		border = theme.textDim
	}
	s.stroke(x, y, w, height, 8, 1, border)

	// A magnifying glass, then the text or the placeholder.
	s.stroke(x+pad, y+11, 11, 11, 5.5, 1.6, theme.textDim)
	s.line(1.6, theme.textDim, x+pad+9.5, y+20.5, x+pad+13, y+24)
	textX := x + pad + 22
	room := w - (textX - x) - pad
	if len(text) > 0 {
		room -= 28
	}
	if len(text) == 0 {
		s.label(placeholder, fontBody, theme.textDim, textX, y, room, height, textLeft)
	} else {
		// While the text is longer than the field, its end is shown, as that is where typing goes on.
		shown := []rune(text)
		for len(shown) > 1 && s.widthOf(string(shown), fontBody) > room-2 {
			shown = shown[1:]
		}
		s.label(string(shown), fontBody, theme.text, textX, y, room, height, textLeft)
		if active {
			s.fill(textX+math.Min(s.widthOf(string(shown), fontBody), room-2)+1, y+9, 1.5, height-18, 0, theme.text)
		}
	}
	if len(text) == 0 && active {
		s.fill(textX, y+9, 1.5, height-18, 0, theme.text)
	}
	if len(text) > 0 {
		clearX := x + w - 32
		s.fillFaded(clearX, y+4, 28, 28, 6, theme.panelHot, s.hoverAmount(id+"-clear", s.hit(id+"-clear", clearX, y+4, 28, 28, clear)))
		s.line(1.6, theme.textDim, clearX+9, y+13, clearX+19, y+23)
		s.line(1.6, theme.textDim, clearX+19, y+13, clearX+9, y+23)
	}
	return height
}
