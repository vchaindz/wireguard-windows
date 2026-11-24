/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

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
	hot := false
	if style != buttonDisabled {
		hot = s.hit(id, x, y, w, h, action)
	}
	pick := func(normal, hovered rgb) rgb {
		if hot {
			return hovered
		}
		return normal
	}
	font, ink := fontBodyBold, themeText
	switch style {
	case buttonGreen:
		s.fill(x, y, w, h, 8, pick(themeGreen, themeGreenHot))
		ink = themeGreenInk
	case buttonAmber:
		s.fill(x, y, w, h, 8, pick(themeAmber, themeAmberHot))
		ink = themeAmberInk
	case buttonRed:
		s.fill(x, y, w, h, 8, pick(themeRed, themeRedHot))
		ink = themeRedInk
	case buttonOutline, buttonDanger:
		if hot {
			s.fill(x, y, w, h, 8, themePanelHot)
		}
		s.stroke(x, y, w, h, 8, 1, themeBorder)
		font = fontBody
		if style == buttonDanger {
			ink = themeRedSoft
		}
	case buttonDisabled:
		s.fill(x, y, w, h, 8, themePanel)
		ink = themeMuted
	case buttonFlat:
		s.fill(x, y, w, h, 6, pick(themePanel, themePanelHot))
		font = fontBody
	}
	s.label(label, font, ink, x+8, y, w-16, h, textCenter)
}

const (
	toggleWidth  = 44
	toggleHeight = 24
)

// toggle draws a switch. Its clickable region is larger than what is drawn.
func (s *scene) toggle(id string, x, y float64, on, enabled bool, action func()) {
	if enabled {
		s.hit(id, x-8, y-10, toggleWidth+16, toggleHeight+20, action)
	}
	if on {
		color := themeGreen
		if !enabled {
			color = themeMuted
		}
		s.fill(x, y, toggleWidth, toggleHeight, toggleHeight/2, color)
		s.fill(x+toggleWidth-21, y+3, 18, 18, 9, themeGreenInk)
	} else {
		s.stroke(x, y, toggleWidth, toggleHeight, toggleHeight/2, 1, themeMuted)
		s.fill(x+4, y+4, 16, 16, 8, themeTextDim)
	}
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
		s.fill(x+1, y+1, 10, 10, 5, themeGreen)
	case glyphBusy:
		s.fill(x+1, y+1, 10, 10, 5, themeTextDim)
	case glyphWarning:
		s.warningSign(x, y, 12, themeAmber, themeAmberInk)
	case glyphAlert:
		s.warningSign(x, y, 12, themeRed, themeRedInk)
	default:
		s.stroke(x+1, y+1, 10, 10, 5, 2, themeMuted)
	}
}

type noticeKind int

const (
	noticeAmber noticeKind = iota
	noticeRed
)

// notice draws a message box with wrapped text and returns its height.
func (s *scene) notice(x, y, w float64, kind noticeKind, title, text string) float64 {
	bg, border, ink, heading, sign, signInk := themeAmberBg, themeAmberBorder, themeAmberText, themeAmberSoft, themeAmber, themeAmberBg
	if kind == noticeRed {
		bg, border, ink, heading, sign, signInk = themeRedBg, themeRedBorder, themeRedText, themeRedSoft, themeRed, themeRedBg
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
	if s.hit("back", 4, 4, 44, 44, action) {
		s.fill(4, 4, 44, 44, 6, themePanelHot)
	}
	s.line(1.8, themeText, 29, 19, 23, 26, 29, 33)
}

// chip draws a pill that filters a list and returns its width. A selected chip is filled.
func (s *scene) chip(id string, x, y float64, label string, selected bool, accent rgb, action func()) float64 {
	const height = 30
	width := s.widthOf(label, fontSmall) + 26
	hot := s.hit(id, x, y, width, height, action)
	ink := accent
	switch {
	case selected:
		s.fill(x, y, width, height, height/2, accent)
		ink = themeBackdrop
	case hot:
		s.fill(x, y, width, height, height/2, themePanelHot)
		s.stroke(x, y, width, height, height/2, 1, themeBorder)
	default:
		s.stroke(x, y, width, height, height/2, 1, themeBorder)
	}
	font := fontSmall
	s.label(label, font, ink, x, y, width, height, textCenter)
	return width
}
