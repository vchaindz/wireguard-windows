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
	"golang.org/x/sys/windows/registry"

	"golang.zx2c4.com/wireguard/windows/manager"
)

// rgb is a color written as 0xRRGGBB.
type rgb uint32

func (c rgb) walk() walk.Color {
	return walk.RGB(byte(c>>16), byte(c>>8), byte(c))
}

// A palette holds one color for each role that the drawn screens use. Drawing reads the current palette, theme,
// so that switching between the dark, the light and the high-contrast palette changes every screen at once.
type palette struct {
	// Grounds: the window, panels on it, and a panel under the mouse.
	backdrop, panelHot, panel rgb
	// line separates parts of a screen; border outlines buttons, chips and the scroll thumb.
	line, border rgb
	// text is for reading, textDim for captions and secondary text, muted for scales and switched-off things.
	text, textDim, muted rgb

	// Green is the color of a working connection and of the main action. greenInk is text on green.
	green, greenHot, greenBg, greenInk rgb
	// The fills under the lines of a graph are their line colors at a quarter of their strength on a panel.
	greenFill, blue, blueFill, violet, violetFill rgb

	// Amber is for something that needs attention, red for something that is broken. Bg, Border and Text make a
	// notice; Soft is the color of text in that color on a ground; Ink is text on a button of that color.
	amber, amberHot, amberBg, amberBorder, amberText, amberSoft, amberInk rgb
	red, redHot, redBg, redBorder, redText, redSoft, redInk               rgb

	// tunnel holds the colors a tunnel can be marked with, in the order of manager.TunnelColors.
	tunnel [tunnelColorCount]rgb

	// dark makes native controls and the window frame use their dark variants.
	dark bool
	// highContrast is set for the palette made from the system colors.
	highContrast bool
}

const tunnelColorCount = len(manager.TunnelColors)

// darkPalette is the original look of the client.
var darkPalette = palette{
	backdrop: 0x111417,
	panel:    0x1A1F24,
	panelHot: 0x222930,
	line:     0x2A3138,
	border:   0x39424C,
	text:     0xF2F4F5,
	textDim:  0xA7B0B8,
	muted:    0x7C8792,

	green:    0x3DDC97,
	greenHot: 0x5BE5AA,
	greenBg:  0x14261F,
	greenInk: 0x0B1F16,

	greenFill:  0x234E41,
	blue:       0x7FB7FF,
	blueFill:   0x33455B,
	violet:     0xC3A6FF,
	violetFill: 0x44415B,

	amber:       0xFFB84D,
	amberHot:    0xFFC670,
	amberBg:     0x2E2410,
	amberBorder: 0x6B5320,
	amberText:   0xF5E3BF,
	amberSoft:   0xFFCB7A,
	amberInk:    0x2A1C00,

	red:       0xFF7A7A,
	redHot:    0xFF9494,
	redBg:     0x2E1414,
	redBorder: 0x7A2E2E,
	redText:   0xFFD9D9,
	redSoft:   0xFF9B9B,
	redInk:    0x2A0808,

	// green, blue, violet, amber, red, teal, pink, gray
	tunnel: [tunnelColorCount]rgb{0x3DDC97, 0x7FB7FF, 0xC3A6FF, 0xFFB84D, 0xFF7A7A, 0x4FD1C5, 0xF58BC8, 0x9AA4AE},

	dark: true,
}

// lightPalette is a light ground with white panels. Its accents are darker than those of the dark palette, so that
// text and marks in them stand out on white, and buttons filled with them carry white text.
var lightPalette = palette{
	backdrop: 0xF3F5F7,
	panel:    0xFFFFFF,
	panelHot: 0xE8ECF0,
	line:     0xDDE2E7,
	border:   0xC2CAD2,
	text:     0x14181C,
	textDim:  0x505A64,
	muted:    0x69737E,

	green:    0x14794A,
	greenHot: 0x0F633C,
	greenBg:  0xE2F3EA,
	greenInk: 0xFFFFFF,

	greenFill:  0xC4E1D2,
	blue:       0x2D69B0,
	blueFill:   0xCAD9EC,
	violet:     0x7048C4,
	violetFill: 0xDBD1F0,

	amber:       0x9A5700,
	amberHot:    0x814800,
	amberBg:     0xFFF2DB,
	amberBorder: 0xE3BD78,
	amberText:   0x4A2F00,
	amberSoft:   0x8F5100,
	amberInk:    0xFFFFFF,

	red:       0xC0312F,
	redHot:    0xA42624,
	redBg:     0xFDECEB,
	redBorder: 0xEDB3B1,
	redText:   0x5E1311,
	redSoft:   0xB0282A,
	redInk:    0xFFFFFF,

	// green, blue, violet, amber, red, teal, pink, gray
	tunnel: [tunnelColorCount]rgb{0x1E8A57, 0x2D69B0, 0x7A4FD0, 0xB06A00, 0xC93838, 0x0E8278, 0xBF3E88, 0x6B7580},
}

// systemColors are the colors of a high-contrast scheme that the high-contrast palette is made of.
type systemColors struct {
	window, windowText, highlight, highlightText, grayText, hotlight rgb
}

// highContrastPalette maps the roles onto the few colors of a high-contrast scheme: grounds are the window color,
// text and lines the window text color, accents the highlight color with its own text color on top, and the soft
// accents, which mark warnings, the hot-light color. Tunnel colors are not shown, as the scheme decides the colors.
func highContrastPalette(c systemColors) palette {
	p := palette{
		backdrop: c.window, panel: c.window, panelHot: c.window,
		line: c.windowText, border: c.windowText,
		text: c.windowText, textDim: c.windowText, muted: c.grayText,

		green: c.highlight, greenHot: c.highlight, greenBg: c.window, greenInk: c.highlightText,
		greenFill: c.window, blue: c.hotlight, blueFill: c.window, violet: c.windowText, violetFill: c.window,

		amber: c.highlight, amberHot: c.highlight, amberBg: c.window, amberBorder: c.windowText,
		amberText: c.windowText, amberSoft: c.hotlight, amberInk: c.highlightText,
		red: c.highlight, redHot: c.highlight, redBg: c.window, redBorder: c.windowText,
		redText: c.windowText, redSoft: c.hotlight, redInk: c.highlightText,

		highContrast: true,
	}
	for i := range p.tunnel {
		p.tunnel[i] = c.windowText
	}
	return p
}

// theme is the palette that drawing uses. It is only changed on the UI thread, by applyThemeSetting.
var theme = &darkPalette

// tunnelColor is the color a tunnel is marked with, if it has one.
func tunnelColor(name string) (rgb, bool) {
	for i, known := range manager.TunnelColors {
		if name == known {
			return theme.tunnel[i], true
		}
	}
	return 0, false
}

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

// useDarkWindowFrame asks Windows to draw the title bar of the window dark, or light again. Older versions ignore
// it. Windows draws the frame anew only when told that it changed.
func useDarkWindowFrame(hwnd win.HWND, dark bool) {
	value := uint32(0)
	if dark {
		value = 1
	}
	dwmSetWindowAttribute(hwnd, dwmwaUseImmersiveDarkMode, value)
	win.SetWindowPos(hwnd, 0, 0, 0, 0, 0, win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE|win.SWP_FRAMECHANGED)
}

// useRoundWindowCorners asks Windows 11 to round the corners of a borderless window.
func useRoundWindowCorners(hwnd win.HWND) {
	dwmSetWindowAttribute(hwnd, dwmwaWindowCornerPreference, dwmwcpRound)
}

// useControlTheme makes the scroll bars and buttons of a native control dark, or gives them their usual look back.
func useControlTheme(hwnd win.HWND, dark bool) {
	if procSetWindowTheme.Find() != nil {
		return
	}
	var name *uint16
	if dark {
		name = windows.StringToUTF16Ptr("DarkMode_Explorer")
	}
	procSetWindowTheme.Call(uintptr(hwnd), uintptr(unsafe.Pointer(name)), 0)
}

// Brushes are kept by color, so that switching the theme back and forth does not make new ones every time.
var themeBrushes = make(map[rgb]walk.Brush)

func themeBrush(color rgb) walk.Brush {
	if brush, ok := themeBrushes[color]; ok {
		return brush
	}
	brush, err := walk.NewSolidColorBrush(color.walk())
	if err != nil {
		return walk.NullBrush()
	}
	themeBrushes[color] = brush
	return brush
}

// styleDialog gives a native dialog the frame and background of the main window.
func styleDialog(dlg *walk.Dialog) {
	useDarkWindowFrame(dlg.Handle(), theme.dark)
	dlg.SetBackground(themeBrush(theme.backdrop))
}

// styleLabels makes labels readable on the background of the theme.
func styleLabels(color rgb, labels ...*walk.TextLabel) {
	for _, label := range labels {
		label.SetTextColor(color.walk())
	}
}

// styleEdits gives line edits the colors of a panel.
func styleEdits(edits ...*walk.LineEdit) {
	for _, edit := range edits {
		edit.SetTextColor(theme.text.walk())
		edit.SetBackground(themeBrush(theme.panel))
	}
}

// styleButtons makes Windows draw push buttons and check boxes in the variant of the theme.
func styleButtons(buttons ...walk.Window) {
	for _, button := range buttons {
		useControlTheme(button.Handle(), theme.dark)
		button.Invalidate()
	}
}

// Choosing the palette

const (
	spiGetHighContrast = 0x0042
	hcfHighContrastOn  = 0x1
	spiSetHighContrast = 0x0043
)

type highContrastInfo struct {
	size        uint32
	flags       uint32
	defaultName *uint16
}

// highContrastOn reports whether Windows is set to a high-contrast scheme.
func highContrastOn() bool {
	info := highContrastInfo{size: uint32(unsafe.Sizeof(highContrastInfo{}))}
	if !win.SystemParametersInfo(spiGetHighContrast, info.size, unsafe.Pointer(&info), 0) {
		return false
	}
	return info.flags&hcfHighContrastOn != 0
}

// sysColor is a system color as an rgb; GetSysColor gives it with red in the lowest byte.
func sysColor(index int) rgb {
	c := win.GetSysColor(index)
	return rgb(c&0xFF)<<16 | rgb(c>>8&0xFF)<<8 | rgb(c>>16&0xFF)
}

const colorHotlight = 26

// appsUseLightTheme reads whether the user chose the light mode for apps. The UI runs in the session of the user,
// also when it runs with an elevated token of that user, so the current-user hive is theirs. Without the value, as
// on versions of Windows before the setting existed, the dark look the client always had is kept.
func appsUseLightTheme() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue("AppsUseLightTheme")
	return err == nil && value != 0
}

// currentThemeSetting is the palette that the settings of Windows ask for.
func currentThemeSetting() *palette {
	if highContrastOn() {
		p := highContrastPalette(systemColors{
			window:        sysColor(win.COLOR_WINDOW),
			windowText:    sysColor(win.COLOR_WINDOWTEXT),
			highlight:     sysColor(win.COLOR_HIGHLIGHT),
			highlightText: sysColor(win.COLOR_HIGHLIGHTTEXT),
			grayText:      sysColor(win.COLOR_GRAYTEXT),
			hotlight:      sysColor(colorHotlight),
		})
		return &p
	}
	if appsUseLightTheme() {
		return &lightPalette
	}
	return &darkPalette
}

// themeChanged holds what is to be done when the palette changes, by a key, for dialogs that are open.
var (
	themeChanged    = make(map[int]func())
	themeChangedKey int
)

// watchTheme makes restyle run whenever the palette changes, until the returned function is called.
func watchTheme(restyle func()) (stop func()) {
	themeChangedKey++
	key := themeChangedKey
	themeChanged[key] = restyle
	return func() { delete(themeChanged, key) }
}

// applyThemeSetting switches to the palette that Windows asks for, if it is not the one in use, and reports
// whether it switched. Views are drawn anew in full, as their kept frames were drawn in the old colors.
func applyThemeSetting() bool {
	next := currentThemeSetting()
	if *next == *theme {
		return false
	}
	theme = next
	for _, restyle := range themeChanged {
		restyle()
	}
	redrawCanvasViews()
	return true
}

// isThemeSettingChange reports whether a WM_SETTINGCHANGE may have changed what the palette depends on: the app
// mode, which Windows announces as "ImmersiveColorSet", or high contrast.
func isThemeSettingChange(wParam, lParam uintptr) bool {
	if wParam == spiSetHighContrast {
		return true
	}
	if lParam == 0 {
		return false
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lParam))) == "ImmersiveColorSet"
}
