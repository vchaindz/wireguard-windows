/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// rgb is a color written as 0xRRGGBB.
type rgb uint32

func (c rgb) walk() walk.Color {
	return walk.RGB(byte(c>>16), byte(c>>8), byte(c))
}

const (
	themeBackdrop rgb = 0x111417
	themePanel    rgb = 0x1A1F24
	themePanelHot rgb = 0x222930
	themeLine     rgb = 0x2A3138
	themeBorder   rgb = 0x39424C
	themeText     rgb = 0xF2F4F5
	themeTextDim  rgb = 0xA7B0B8
	themeMuted    rgb = 0x7C8792

	themeGreen    rgb = 0x3DDC97
	themeGreenHot rgb = 0x5BE5AA
	themeGreenBg  rgb = 0x14261F
	themeGreenInk rgb = 0x0B1F16

	themeAmber       rgb = 0xFFB84D
	themeAmberHot    rgb = 0xFFC670
	themeAmberBg     rgb = 0x2E2410
	themeAmberBorder rgb = 0x6B5320
	themeAmberText   rgb = 0xF5E3BF
	themeAmberSoft   rgb = 0xFFCB7A
	themeAmberInk    rgb = 0x2A1C00

	themeRed       rgb = 0xFF7A7A
	themeRedHot    rgb = 0xFF9494
	themeRedBg     rgb = 0x2E1414
	themeRedBorder rgb = 0x7A2E2E
	themeRedText   rgb = 0xFFD9D9
	themeRedSoft   rgb = 0xFF9B9B
	themeRedInk    rgb = 0x2A0808
)

type themeFont int

const (
	fontBody themeFont = iota
	fontBodyBold
	fontSmall
	fontCaps
	fontHeading
	fontTitle
	fontMono
	themeFontCount
)

type fontAndDPI struct {
	font themeFont
	dpi  int
}

var themeFontHandles = make(map[fontAndDPI]win.HFONT)

// handle returns the GDI font of the theme for a DPI. Fonts are created on first use and live as long as the process.
func (f themeFont) handle(dpi int) win.HFONT {
	key := fontAndDPI{f, dpi}
	if handle, ok := themeFontHandles[key]; ok {
		return handle
	}
	spec := [themeFontCount]struct {
		family string
		points float64
		weight int32
	}{
		fontBody:     {"Segoe UI", 10, 400},
		fontBodyBold: {"Segoe UI", 10, 600},
		fontSmall:    {"Segoe UI", 9, 400},
		fontCaps:     {"Segoe UI", 8, 600},
		fontHeading:  {"Segoe UI", 13, 600},
		fontTitle:    {"Segoe UI", 20, 600},
		fontMono:     {"Consolas", 9, 400},
	}[f]
	lf := win.LOGFONT{
		LfHeight:  -int32(spec.points*float64(dpi)/72 + 0.5),
		LfWeight:  spec.weight,
		LfCharSet: win.DEFAULT_CHARSET,
		LfQuality: win.CLEARTYPE_QUALITY,
	}
	copy(lf.LfFaceName[:len(lf.LfFaceName)-1], windows.StringToUTF16(spec.family))
	handle := win.CreateFontIndirect(&lf)
	themeFontHandles[key] = handle
	return handle
}

var (
	dwmapi                    = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	uxtheme                   = windows.NewLazySystemDLL("uxtheme.dll")
	procSetWindowTheme        = uxtheme.NewProc("SetWindowTheme")
)

const (
	dwmwaUseImmersiveDarkMode   = 20
	dwmwaWindowCornerPreference = 33
	dwmwcpRound                 = 2
)

func dwmSetWindowAttribute(hwnd win.HWND, attribute, value uint32) {
	if procDwmSetWindowAttribute.Find() != nil {
		return
	}
	procDwmSetWindowAttribute.Call(uintptr(hwnd), uintptr(attribute), uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value))
}

// useDarkWindowFrame asks Windows to draw the title bar of the window dark. Older versions ignore it.
func useDarkWindowFrame(hwnd win.HWND) {
	dwmSetWindowAttribute(hwnd, dwmwaUseImmersiveDarkMode, 1)
}

// useRoundWindowCorners asks Windows 11 to round the corners of a borderless window.
func useRoundWindowCorners(hwnd win.HWND) {
	dwmSetWindowAttribute(hwnd, dwmwaWindowCornerPreference, dwmwcpRound)
}

// useDarkControlTheme makes the scroll bars of a native control dark.
func useDarkControlTheme(hwnd win.HWND) {
	if procSetWindowTheme.Find() != nil {
		return
	}
	procSetWindowTheme.Call(uintptr(hwnd), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("DarkMode_Explorer"))), 0)
}

func themeBrush(color rgb) walk.Brush {
	brush, err := walk.NewSolidColorBrush(color.walk())
	if err != nil {
		return walk.NullBrush()
	}
	return brush
}
