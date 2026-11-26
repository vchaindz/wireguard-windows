/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"math"
	"testing"

	"golang.zx2c4.com/wireguard/windows/manager"
)

// relativeLuminance is the luminance of a color as WCAG 2 defines it.
func relativeLuminance(c rgb) float64 {
	channel := func(v byte) float64 {
		s := float64(v) / 255
		if s <= 0.04045 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(byte(c>>16)) + 0.7152*channel(byte(c>>8)) + 0.0722*channel(byte(c))
}

// contrastRatio is the WCAG contrast ratio of two colors, from 1 to 21.
func contrastRatio(a, b rgb) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

type contrastPair struct {
	what   string
	fg, bg rgb
	// least is 4.5 for text and 3 for large titles and for marks that are not text.
	least float64
}

const (
	textContrast = 4.5
	markContrast = 3
)

// contrastPairs are the colors that the screens put on top of each other, as they are drawn.
func contrastPairs(p *palette) []contrastPair {
	grounds := []struct {
		name  string
		color rgb
	}{{"backdrop", p.backdrop}, {"panel", p.panel}, {"hovered panel", p.panelHot}}
	var pairs []contrastPair
	add := func(what string, fg, bg rgb, least float64) {
		pairs = append(pairs, contrastPair{what, fg, bg, least})
	}
	for _, ground := range grounds {
		on := " on " + ground.name
		add("text"+on, p.text, ground.color, textContrast)
		add("dim text"+on, p.textDim, ground.color, textContrast)
		add("green status text"+on, p.green, ground.color, textContrast)
		add("amber text"+on, p.amberSoft, ground.color, textContrast)
		add("red text"+on, p.redSoft, ground.color, textContrast)
		add("muted mark"+on, p.muted, ground.color, markContrast)
		add("focus ring"+on, p.text, ground.color, markContrast)
		for i, name := range manager.TunnelColors {
			add("tunnel color "+name+on, p.tunnel[i], ground.color, markContrast)
		}
	}
	// Scales and disabled buttons, both on panels.
	add("muted text on panel", p.muted, p.panel, textContrast)

	// The state of the hero and of the tray popup header: title, subtitle, ring and the button drawn in the accent.
	for _, state := range []struct {
		name           string
		accent, ground rgb
	}{{"connected", p.green, p.greenBg}, {"problem", p.amber, p.amberBg}, {"cut off", p.red, p.redBg}, {"inactive", p.muted, p.panel}, {"busy", p.textDim, p.panel}} {
		add(state.name+": title", p.text, state.ground, textContrast)
		add(state.name+": subtitle", p.textDim, state.ground, textContrast)
		add(state.name+": ring", state.accent, state.ground, markContrast)
		if state.name != "inactive" && state.name != "busy" {
			add(state.name+": turn-off button text", state.accent, state.ground, textContrast)
		}
	}
	add("title on backdrop", p.text, p.backdrop, markContrast)

	// Notices and the update banner.
	add("amber notice text", p.amberText, p.amberBg, textContrast)
	add("amber notice title", p.amberSoft, p.amberBg, textContrast)
	add("amber notice sign", p.amber, p.amberBg, markContrast)
	add("amber notice sign ink", p.amberBg, p.amber, markContrast)
	add("red notice text", p.redText, p.redBg, textContrast)
	add("red notice title", p.redSoft, p.redBg, textContrast)
	add("red notice sign", p.red, p.redBg, markContrast)
	add("red notice sign ink", p.redBg, p.red, markContrast)

	// Buttons, plain and hovered, and the marks drawn like them.
	add("green button ink", p.greenInk, p.green, textContrast)
	add("green button ink hovered", p.greenInk, p.greenHot, textContrast)
	add("amber button ink", p.amberInk, p.amber, textContrast)
	add("amber button ink hovered", p.amberInk, p.amberHot, textContrast)
	add("red button ink", p.redInk, p.red, textContrast)
	add("red button ink hovered", p.redInk, p.redHot, textContrast)
	add("warning sign ink", p.amberInk, p.amber, markContrast)
	add("alert sign ink", p.redInk, p.red, markContrast)
	add("switch knob on", p.greenInk, p.green, markContrast)
	add("switch knob off", p.textDim, p.panel, markContrast)

	// Chips: selected ones carry the ground color on their accent.
	add("selected chip ink on text", p.backdrop, p.text, textContrast)
	add("selected chip ink on amber", p.backdrop, p.amberSoft, textContrast)

	// Charts, on panels.
	for _, series := range []struct {
		name  string
		color rgb
	}{{"received", p.green}, {"sent", p.blue}, {"latency", p.violet}, {"loss", p.red}} {
		add("chart "+series.name+" line", series.color, p.panel, markContrast)
	}
	add("chart hover line", p.textDim, p.panel, markContrast)
	return pairs
}

// highContrastSchemes are two of the schemes that Windows ships, black and white, with the colors it gives them.
var highContrastSchemes = map[string]systemColors{
	"high contrast black": {window: 0x000000, windowText: 0xFFFFFF, highlight: 0x1AEBFF, highlightText: 0x000000, grayText: 0x3FF23F, hotlight: 0xFFFF00},
	"high contrast white": {window: 0xFFFFFF, windowText: 0x000000, highlight: 0x37006E, highlightText: 0xFFFFFF, grayText: 0x600000, hotlight: 0x00009F},
}

func TestPaletteContrast(t *testing.T) {
	palettes := map[string]*palette{"dark": &darkPalette, "light": &lightPalette}
	for name, colors := range highContrastSchemes {
		p := highContrastPalette(colors)
		palettes[name] = &p
	}
	for name, p := range palettes {
		lowest := math.Inf(1)
		for _, pair := range contrastPairs(p) {
			ratio := contrastRatio(pair.fg, pair.bg)
			lowest = math.Min(lowest, ratio/pair.least)
			if ratio < pair.least {
				t.Errorf("%s: %s: %06X on %06X is %.2f:1, needs %.1f:1", name, pair.what, uint32(pair.fg), uint32(pair.bg), ratio, pair.least)
			}
			if testing.Verbose() {
				fmt.Printf("%-20s %-45s %06X on %06X %5.2f:1\n", name, pair.what, uint32(pair.fg), uint32(pair.bg), ratio)
			}
		}
		t.Logf("%s: the closest pair has %.2f times the contrast it needs", name, lowest)
	}
}

func TestContrastRatio(t *testing.T) {
	if ratio := contrastRatio(0x000000, 0xFFFFFF); math.Abs(ratio-21) > 1e-9 {
		t.Errorf("black on white: %v", ratio)
	}
	if ratio := contrastRatio(0x777777, 0xFFFFFF); math.Abs(ratio-4.48) > 0.01 {
		t.Errorf("#777 on white: %v", ratio)
	}
}

// The palette in use can be compared with another to tell whether a setting changed it.
func TestPaletteSwitch(t *testing.T) {
	defer func(saved *palette) { theme = saved }(theme)
	theme = &darkPalette
	if color, ok := tunnelColor("teal"); !ok || color != darkPalette.tunnel[5] {
		t.Errorf("teal in the dark palette: %06X, %v", uint32(color), ok)
	}
	theme = &lightPalette
	if color, ok := tunnelColor("teal"); !ok || color != lightPalette.tunnel[5] {
		t.Errorf("teal in the light palette: %06X, %v", uint32(color), ok)
	}
	if _, ok := tunnelColor(""); ok {
		t.Error("no color has a color")
	}
	if *theme == darkPalette {
		t.Error("the light palette equals the dark one")
	}
	hc := highContrastPalette(highContrastSchemes["high contrast black"])
	if !hc.highContrast || hc.dark || hc.backdrop != 0 || hc.text != 0xFFFFFF {
		t.Errorf("high contrast palette: %+v", hc)
	}
}
