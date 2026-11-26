/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"image"
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/lxn/walk"
	"github.com/lxn/win"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
)

// renderScene draws a scene the way a canvasView does, but into an image instead of a window.
func renderScene(t *testing.T, width, height, scale float64, build func(s *scene, width, height float64)) (*scene, image.Image) {
	return renderSceneWith(t, width, height, scale, 0, "", build)
}

// renderSceneWith also scrolls the scene and shows the focus ring on a region.
func renderSceneWith(t *testing.T, width, height, scale, scroll float64, focus string, build func(s *scene, width, height float64)) (*scene, image.Image) {
	return renderSceneMouse(t, width, height, scale, scroll, focus, nil, build)
}

// renderSceneMouse also puts the mouse at a point, if one is given. As in a view, the region under it is found
// in a first frame and is hot in the second.
func renderSceneMouse(t *testing.T, width, height, scale, scroll float64, focus string, mouse *[2]float64, build func(s *scene, width, height float64)) (*scene, image.Image) {
	dpi := int(96*scale + 0.5)
	measureHDC := win.CreateCompatibleDC(0)
	defer win.DeleteDC(measureHDC)

	s := &scene{scroll: scroll}
	if mouse != nil {
		first, _ := renderSceneMouse(t, width, height, scale, scroll, "", nil, build)
		s.mouseX, s.mouseY, s.mouseIn = mouse[0], mouse[1], true
		if hit := first.hitAt(mouse[0], mouse[1]); hit != nil {
			s.hot = hit.id
		}
	}
	s.measure = func(text string, font themeFont, width float64) float64 {
		return measureWrapped(measureHDC, dpi, text, font, width)
	}
	s.lineWidth = func(text string, font themeFont) float64 {
		return measureLine(measureHDC, dpi, text, font)
	}
	build(s, width, height)
	if height == 0 {
		height = s.height
		s.shapes, s.texts, s.hits = nil, nil, nil
		build(s, width, height)
	}
	if len(focus) > 0 {
		if s.hitByID(focus) == nil {
			t.Errorf("no region %q to focus", focus)
		}
		s.focusRing(focus)
	}

	bitmap, err := walk.NewBitmapFromImageForDPI(s.rasterize(int(width*scale+0.5), int(height*scale+0.5), scale, theme.backdrop), dpi)
	if err != nil {
		t.Fatal(err)
	}
	defer bitmap.Dispose()
	canvas, err := walk.NewCanvasFromImage(bitmap)
	if err != nil {
		t.Fatal(err)
	}
	s.drawTexts(canvas.HDC(), scale, dpi)
	canvas.Dispose()
	img, err := bitmap.ToImage()
	if err != nil {
		t.Fatal(err)
	}
	// Drawing text with GDI leaves the alpha channel of the touched pixels at zero.
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 0xff
	}
	return s, img
}

func sampleConfig(name, address string, handshakeAgo time.Duration, rx, tx conf.Bytes) *conf.Config {
	config := &conf.Config{Name: name}
	config.Interface.PrivateKey = *conf.NewPrivateKey()
	config.Interface.Addresses = []netip.Prefix{netip.MustParsePrefix(address)}
	config.Interface.DNS = []netip.Addr{netip.MustParseAddr("10.8.0.1")}
	config.Interface.MTU = 1420
	peer := conf.Peer{
		PublicKey:           *conf.NewPrivateKey(),
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("192.168.10.0/24")},
		Endpoint:            conf.Endpoint{Host: "vpn.example.com", Port: 51820},
		PersistentKeepalive: 25,
		RxBytes:             rx,
		TxBytes:             tx,
	}
	if handshakeAgo > 0 {
		peer.LastHandshakeTime = conf.HandshakeTime(time.Now().Add(-handshakeAgo).UnixNano())
	}
	config.Peers = []conf.Peer{peer}
	return config
}

// renderPalettes are the palettes that every render is made in, with the suffix of their file names.
var renderPalettes = []struct {
	suffix  string
	palette *palette
}{{"", &darkPalette}, {"-light", &lightPalette}}

// inEachPalette runs a render once per palette, with theme set to it.
func inEachPalette(t *testing.T, render func(t *testing.T, suffix string)) {
	saved := theme
	defer func() { theme = saved }()
	for _, p := range renderPalettes {
		theme = p.palette
		render(t, p.suffix)
	}
}

// TestRenderScreens draws every screen with sample tunnels in several states. Set WG_UI_RENDER_DIR
// to a directory to have the results written there as PNG files for looking at.
func TestRenderScreens(t *testing.T) {
	inEachPalette(t, renderScreens)
}

func renderScreens(t *testing.T, suffix string) {
	wasAdmin := IsAdmin
	IsAdmin = true
	defer func() { IsAdmin = wasAdmin }()

	entry := func(name string, state manager.TunnelState, health manager.TunnelHealth) tunnelEntry {
		return tunnelEntry{tunnel: manager.Tunnel{Name: name}, state: state, health: health}
	}
	connected := entry("office", manager.TunnelStarted, manager.TunnelHealthConnected)
	connected.config = sampleConfig("office", "10.8.0.2/24", 42*time.Second, 1331439862, 228589568)
	connected.metrics = manager.TunnelMetrics{
		ActiveSince:        time.Now().Add(-3*time.Hour - 12*time.Minute),
		ConnectedSince:     time.Now().Add(-47 * time.Minute),
		LastActiveEnd:      time.Now().Add(-26 * time.Hour),
		LastActiveDuration: 95 * time.Minute,
		ConnectionFailures: 2,
		Reconnects:         1,
		InDiscards:         3,
	}
	connected.settings, connected.settingsLoaded, connected.probingAllowed = manager.TunnelSettings{Color: "blue", Favorite: true}, true, true
	officeSamples := tunnelSamples{seconds: sampleSeries(time.Now(), 120, time.Second, nil)}
	unstable := connected
	unstable.unstable = true
	conflict := connected
	conflict.conflictSuspected = true
	waiting := entry("home-lab", manager.TunnelStarted, manager.TunnelHealthWaitingForPeer)
	waiting.config = sampleConfig("home-lab", "10.20.0.5/32", 0, 0, 1516)
	blocked := entry("customer-vpn", manager.TunnelStarted, manager.TunnelHealthNoConnectionNetworkBlocked)
	blocked.config = sampleConfig("customer-vpn", "172.16.4.9/32", 6*time.Minute, 52428800, 9437184)
	stopped := func(name string) tunnelEntry {
		e := entry(name, manager.TunnelStopped, manager.TunnelHealthUnknown)
		switch name {
		case "backup-site":
			e.metrics = manager.TunnelMetrics{LastActiveEnd: time.Now().Add(-2 * time.Hour), LastActiveDuration: 35 * time.Minute}
			e.settings = manager.TunnelSettings{Color: "violet", Favorite: true}
		case "customer-vpn":
			e.settings = manager.TunnelSettings{Color: "amber"}
		}
		return e
	}

	for _, c := range []struct {
		name    string
		entries []tunnelEntry
		global  manager.TunnelState
		details string
		update  bool
	}{
		{"connected", []tunnelEntry{stopped("backup-site"), stopped("customer-vpn"), stopped("home-lab"), unstable}, manager.TunnelStarted, "", false},
		{"inactive", []tunnelEntry{stopped("backup-site"), stopped("customer-vpn"), stopped("home-lab"), stopped("office")}, manager.TunnelStopped, "", true},
		{"waiting", []tunnelEntry{stopped("backup-site"), waiting, stopped("office")}, manager.TunnelStarted, "", false},
		{"cutoff", []tunnelEntry{stopped("backup-site"), blocked, stopped("office")}, manager.TunnelStarted, "", false},
		{"activating", []tunnelEntry{stopped("backup-site"), entry("office", manager.TunnelStarting, manager.TunnelHealthUnknown)}, manager.TunnelStarting, "", false},
		{"empty", nil, manager.TunnelStopped, "", false},
		{"empty-operator", nil, manager.TunnelStopped, "", false},
		{"details", []tunnelEntry{stopped("backup-site"), conflict}, manager.TunnelStarted, "office", false},
	} {
		IsAdmin = c.name != "empty-operator"
		mtw := &ManageTunnelsWindow{model: &appModel{entries: c.entries, globalState: c.global, updateAvailable: c.update, samples: map[string]tunnelSamples{"office": officeSamples}}}
		build := mtw.buildStatus
		if len(c.details) > 0 {
			mtw.screen, mtw.detailsName = screenDetails, c.details
			build = mtw.buildDetails
		}
		popup := &TrayPopup{mtw: mtw}
		for _, scale := range []float64{1, 1.5} {
			for kind, render := range map[string]func() (*scene, image.Image){
				"window": func() (*scene, image.Image) { return renderScene(t, 524, 820, scale, build) },
				"tray":   func() (*scene, image.Image) { return renderScene(t, trayPopupWidth, 0, scale, popup.build) },
			} {
				s, img := render()
				if len(s.shapes) == 0 || len(s.texts) == 0 || len(s.hits) == 0 {
					t.Errorf("%s %s: nothing drawn", c.name, kind)
				}
				for _, hit := range s.hits {
					if hit.rect.w <= 0 || hit.rect.h <= 0 {
						t.Errorf("%s %s: empty clickable region %q", c.name, kind, hit.id)
					}
				}
				if dir := os.Getenv("WG_UI_RENDER_DIR"); len(dir) > 0 && (scale == 1 || c.name == "connected") {
					file, err := os.Create(filepath.Join(dir, c.name+"-"+kind+suffix+map[float64]string{1: "", 1.5: "@150"}[scale]+".png"))
					if err != nil {
						t.Fatal(err)
					}
					if err := png.Encode(file, img); err != nil {
						t.Fatal(err)
					}
					file.Close()
				}
			}
		}
	}
}

func TestSceneHitTesting(t *testing.T) {
	s := &scene{}
	clicked := ""
	s.hit("below", 0, 0, 100, 100, func() { clicked = "below" })
	s.setClip(0, 0, 100, 40)
	s.hit("clipped", 10, 10, 50, 50, func() { clicked = "clipped" })
	s.clearClip()
	for _, c := range []struct {
		x, y float64
		want string
	}{
		{20, 20, "clipped"},
		{20, 50, "below"},
		{70, 20, "below"},
		{150, 20, ""},
	} {
		clicked = ""
		if hit := s.hitAt(c.x, c.y); hit != nil {
			hit.action()
		}
		if clicked != c.want {
			t.Errorf("at %v,%v: hit %q, want %q", c.x, c.y, clicked, c.want)
		}
	}
}

func TestHeroPrefersProblemTunnel(t *testing.T) {
	entry := func(name string, state manager.TunnelState, health manager.TunnelHealth) tunnelEntry {
		return tunnelEntry{tunnel: manager.Tunnel{Name: name}, state: state, health: health}
	}
	unstable := entry("d-unstable", manager.TunnelStarted, manager.TunnelHealthConnected)
	unstable.unstable = true
	for _, c := range []struct {
		entries []tunnelEntry
		want    string
	}{
		{nil, ""},
		{[]tunnelEntry{entry("a", manager.TunnelStopped, manager.TunnelHealthUnknown)}, ""},
		{[]tunnelEntry{entry("a", manager.TunnelStopped, manager.TunnelHealthUnknown), entry("b", manager.TunnelStarting, manager.TunnelHealthUnknown)}, "b"},
		{[]tunnelEntry{entry("a", manager.TunnelStarting, manager.TunnelHealthUnknown), entry("b", manager.TunnelStarted, manager.TunnelHealthUnverified)}, "b"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthConnected), entry("b", manager.TunnelStarted, manager.TunnelHealthConnected)}, "a"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthConnected), unstable}, "d-unstable"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthConnected), entry("b", manager.TunnelStarted, manager.TunnelHealthWaitingForPeer), unstable}, "b"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthWaitingForPeer), entry("b", manager.TunnelStarted, manager.TunnelHealthNoConnection), entry("c", manager.TunnelStarted, manager.TunnelHealthNoConnectionNetworkBlocked)}, "c"},
	} {
		got := ""
		if hero := (&appModel{entries: c.entries}).hero(); hero != nil {
			got = hero.tunnel.Name
		}
		if got != c.want {
			t.Errorf("%v: hero %q, want %q", c.entries, got, c.want)
		}
	}
}

func writePNG(t *testing.T, name string, img image.Image) {
	dir := os.Getenv("WG_UI_RENDER_DIR")
	if len(dir) == 0 {
		return
	}
	file, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := png.Encode(file, img); err != nil {
		t.Fatal(err)
	}
}

// TestRenderKeyboardAndScrolling draws the focus ring, a scrolled list with its thumb, and the log filters.
func TestRenderKeyboardAndScrolling(t *testing.T) {
	inEachPalette(t, renderKeyboardAndScrolling)
}

func renderKeyboardAndScrolling(t *testing.T, suffix string) {
	wasAdmin := IsAdmin
	IsAdmin = true
	defer func() { IsAdmin = wasAdmin }()

	office := tunnelEntry{tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStarted, health: manager.TunnelHealthConnected}
	office.config = sampleConfig("office", "10.8.0.2/24", 42*time.Second, 1331439862, 228589568)
	entries := []tunnelEntry{office}
	for _, name := range []string{"site-01", "site-02", "site-03", "site-04", "site-05", "site-06", "site-07", "site-08", "site-09", "site-10", "site-11", "site-12"} {
		entries = append(entries, tunnelEntry{tunnel: manager.Tunnel{Name: name}, state: manager.TunnelStopped})
	}
	mtw := &ManageTunnelsWindow{model: &appModel{entries: entries, globalState: manager.TunnelStarted}}
	mtw.logPage = &LogPage{model: &logModel{filterTunnel: "office"}}
	popup := &TrayPopup{mtw: mtw}

	s, img := renderSceneWith(t, 524, 740, 1, 0, "hero-toggle", mtw.buildStatus)
	if s.maxScroll <= 0 {
		t.Error("a long list of tunnels does not scroll")
	}
	writePNG(t, "focus-button"+suffix, img)

	s, img = renderSceneWith(t, 524, 740, 1, 230, "toggle:site-05", mtw.buildStatus)
	if hit := s.hitByID("toggle:site-05"); hit == nil || !hit.clipped || hit.rect.y < hit.clip.y || hit.rect.y > hit.clip.y+hit.clip.h {
		t.Error("the focused switch is not inside the scrolled list")
	}
	writePNG(t, "focus-scrolled"+suffix, img)

	s, img = renderSceneWith(t, trayPopupWidth, 0, 1, 0, "row:site-02", popup.build)
	if s.maxScroll <= 0 {
		t.Error("a long list of tunnels does not scroll in the tray popup")
	}
	writePNG(t, "focus-tray"+suffix, img)

	s, img = renderScene(t, 524, logFiltersHeight, 1, mtw.buildLogFilters)
	order := s.focusOrder()
	if len(order) < 3 || order[0] != "all" || order[1] != "warnings" || order[2] != "tunnel:office" {
		t.Errorf("log filters: got %v", order)
	}
	writePNG(t, "log-filters"+suffix, img)
}

func TestFocusOrder(t *testing.T) {
	s := &scene{}
	s.hit("a", 0, 0, 10, 10, func() {})
	s.hit("disabled", 0, 10, 10, 10, nil)
	s.hit("b", 0, 20, 10, 10, func() {})
	s.hit("a", 0, 30, 10, 10, func() {})
	if order := s.focusOrder(); len(order) != 2 || order[0] != "a" || order[1] != "b" {
		t.Errorf("got %v, want [a b]", order)
	}
}

func TestLogFilter(t *testing.T) {
	mdl := &logModel{}
	for _, line := range []string{
		"[TUN] [office] Starting WireGuard",
		"[MGR] [office] Connection check: handshake completed, tunnel is connected",
		"[MGR] [home-lab] Warning: connection check: no peer answers; routes have not been applied, so the rest of the network is unaffected",
		"[MGR] [office] Warning: connection check: the session was lost and re-established; the connection is unstable",
		"[MGR] [home-lab] Error: connection check: no peer completes a handshake, and this tunnel takes over all traffic, so the network is cut off",
		"[MGR] An update is available",
		"[MGR] Error: unable to create pipe: access denied",
	} {
		mdl.all = append(mdl.all, ringlogger.FollowLine{Line: line})
	}
	for _, c := range []struct {
		tunnel       string
		warningsOnly bool
		want         int
	}{
		{"", false, 7},
		{"office", false, 3},
		{"", true, 4},
		{"office", true, 1},
		{"home-lab", true, 2},
		// A name that is only part of another one does not match.
		{"lab", false, 0},
		{"nowhere", false, 0},
	} {
		mdl.filterTunnel, mdl.warningsOnly = c.tunnel, c.warningsOnly
		mdl.applyFilter()
		if len(mdl.items) != c.want {
			t.Errorf("tunnel %q, warnings only %v: %d lines, want %d", c.tunnel, c.warningsOnly, len(mdl.items), c.want)
		}
	}
}

// Destroying the main window disposes of it, and with it of the model, a second time.
func TestModelDisposeTwice(t *testing.T) {
	model := &appModel{
		refreshRequests:  make(chan struct{}, 1),
		tunnelChangedCB:  &manager.TunnelChangeCallback{},
		tunnelHealthCB:   &manager.TunnelHealthCallback{},
		tunnelsChangedCB: &manager.TunnelsChangeCallback{},
	}
	model.dispose()
	model.dispose()
	model.refresh()
}

func TestFormatDuration(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0 s"},
		{42 * time.Second, "42 s"},
		{59*time.Minute + 59*time.Second, "59 min"},
		{3*time.Hour + 12*time.Minute, "3 h 12 min"},
		{50 * time.Hour, "2 d 2 h"},
	} {
		if got := formatDuration(c.d); got != c.want {
			t.Errorf("%v: got %q, want %q", c.d, got, c.want)
		}
	}
}

// TestRenderTrayIcons draws the tray icon of every state at the sizes of the common DPIs from the logo file, and a
// contact sheet that shows them enlarged, pixel by pixel, on a dark and on a light taskbar.
func TestRenderTrayIcons(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("icon", "wireguard.ico"))
	if err != nil {
		t.Fatal(err)
	}
	frames, err := icoFileFrames(data)
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{16, 20, 24, 28, 32}
	const zoom, gap = 6, 8
	taskbars := []rgb{0x202020, 0xEEEEEE}
	cell := 32*zoom + gap
	sheet := image.NewRGBA(image.Rect(0, 0, int(trayStateCount)*cell*len(taskbars)+gap, len(sizes)*cell+gap))
	for i := range sheet.Pix {
		sheet.Pix[i] = 0x80
	}
	for row, size := range sizes {
		logo, err := logoFromFrames(frames, size)
		if err != nil {
			t.Fatal(err)
		}
		if logo.Bounds().Dx() != size || logo.Bounds().Dy() != size {
			t.Fatalf("logo at %d px is %v", size, logo.Bounds())
		}
		for state := trayState(0); state < trayStateCount; state++ {
			img := trayIconImage(state, logo)
			if size == 16 || size == 24 || size == 32 {
				writePNG(t, "trayicon-"+strconv.Itoa(int(state))+"-"+strconv.Itoa(size), img)
			}
			for b, taskbar := range taskbars {
				left, top := gap+(b*int(trayStateCount)+int(state))*cell, gap+row*cell
				for y := 0; y < size*zoom; y++ {
					for x := 0; x < size*zoom; x++ {
						pixel := img.Pix[img.PixOffset(x/zoom, y/zoom):]
						alpha := float64(pixel[3]) / 255
						out := sheet.Pix[sheet.PixOffset(left+x, top+y):]
						for c, shift := range []uint{16, 8, 0} {
							out[c] = byte(float64(pixel[c])*alpha + float64(byte(taskbar>>shift))*(1-alpha) + 0.5)
						}
						out[3] = 0xff
					}
				}
			}
		}
	}
	writePNG(t, "trayicons-sheet", sheet)
	overlays := image.NewRGBA(image.Rect(0, 0, int(trayStateCount)*(16*zoom+gap)+gap, 16*zoom+2*gap))
	for i := range overlays.Pix {
		overlays.Pix[i] = 0x80
	}
	for state := trayConnected; state < trayStateCount; state++ {
		img := overlayImage(state, 16)
		left := gap + int(state-trayConnected)*(16*zoom+gap)
		for y := 0; y < 16*zoom; y++ {
			for x := 0; x < 16*zoom; x++ {
				pixel := img.Pix[img.PixOffset(x/zoom, y/zoom):]
				alpha := float64(pixel[3]) / 255
				out := overlays.Pix[overlays.PixOffset(left+x, gap+y):]
				for c := 0; c < 3; c++ {
					out[c] = byte(float64(pixel[c])*alpha + 0x80*(1-alpha) + 0.5)
				}
				out[3] = 0xff
			}
		}
	}
	writePNG(t, "trayicons-overlays", overlays)

	// The marks differ in shape as well as in color, and "off" has no color at all.
	logo, _ := logoFromFrames(frames, 16)
	off := trayIconImage(trayOff, logo)
	for i := 0; i < len(off.Pix); i += 4 {
		if off.Pix[i] != off.Pix[i+1] || off.Pix[i+1] != off.Pix[i+2] {
			t.Fatal("the icon of no active tunnel is not grey")
		}
	}
}

func TestPickIconFrame(t *testing.T) {
	frames := []iconFrame{{256, nil}, {16, nil}, {32, nil}, {48, nil}}
	for _, c := range []struct{ want, got int }{{16, 16}, {32, 32}, {20, 32}, {40, 48}, {64, 256}, {512, 256}, {8, 16}} {
		if frame, _ := pickIconFrame(frames, c.want); frame.size != c.got {
			t.Errorf("for %d px: frame of %d, want %d", c.want, frame.size, c.got)
		}
	}
}

func TestTrayState(t *testing.T) {
	entry := func(name string, state manager.TunnelState, health manager.TunnelHealth) tunnelEntry {
		return tunnelEntry{tunnel: manager.Tunnel{Name: name}, state: state, health: health}
	}
	unstable := entry("u", manager.TunnelStarted, manager.TunnelHealthConnected)
	unstable.unstable = true
	for _, c := range []struct {
		entries []tunnelEntry
		want    trayState
		which   string
	}{
		{nil, trayOff, ""},
		{[]tunnelEntry{entry("a", manager.TunnelStopped, 0)}, trayOff, ""},
		{[]tunnelEntry{entry("a", manager.TunnelStopped, 0), entry("b", manager.TunnelStarted, manager.TunnelHealthConnected)}, trayConnected, "b"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthUnverified)}, trayConnected, "a"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthConnected), entry("b", manager.TunnelStarting, 0)}, trayBusy, "b"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthConnected), unstable}, trayProblem, "u"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthWaitingForPeer), entry("b", manager.TunnelStopping, 0)}, trayProblem, "a"},
		{[]tunnelEntry{entry("a", manager.TunnelStarted, manager.TunnelHealthNoConnection), entry("b", manager.TunnelStarted, manager.TunnelHealthNoConnectionNetworkBlocked)}, trayCutOff, "b"},
	} {
		state, which := (&appModel{entries: c.entries}).trayState()
		name := ""
		if which != nil {
			name = which.tunnel.Name
		}
		if state != c.want || name != c.which {
			t.Errorf("%v: state %d of %q, want %d of %q", c.entries, state, name, c.want, c.which)
		}
	}
}

func TestTrayToolTip(t *testing.T) {
	now := time.Now()
	office := tunnelEntry{tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStarted, health: manager.TunnelHealthConnected}
	office.metrics.ConnectedSince = now.Add(-47 * time.Minute)
	model := &appModel{
		entries: []tunnelEntry{office, {tunnel: manager.Tunnel{Name: "home"}, state: manager.TunnelStarting}},
		samples: map[string]tunnelSamples{"office": {seconds: sampleSeries(now, 10, time.Second, nil)}},
	}
	// The tunnel being switched is the one that is shown, with the other active one counted.
	if tip := model.trayToolTip(now); tip != "WireGuard: Activating…\nhome (+1)" {
		t.Errorf("busy: %q", tip)
	}
	model.entries = model.entries[:1]
	tip := model.trayToolTip(now)
	lines := strings.Split(tip, "\n")
	if len(lines) != 3 || lines[0] != "WireGuard: Connected" || lines[1] != "office · connected for 47 min" || !strings.HasPrefix(lines[2], "In ") {
		t.Errorf("connected: %q", tip)
	}
	model.entries[0].tunnel.Name = strings.Repeat("long-name-", 20)
	if tip := model.trayToolTip(now); len(utf16.Encode([]rune(tip))) > trayToolTipLimit || !strings.HasSuffix(tip, "…") {
		t.Errorf("long name: %d units: %q", len(utf16.Encode([]rune(tip))), tip)
	}
	if tip := (&appModel{}).trayToolTip(now); tip != "WireGuard: Not connected" {
		t.Errorf("off: %q", tip)
	}
}

// TestRenderDetailsInsights draws the whole details screen of a started tunnel with its path, its events and a
// finished test, and one with a test in progress and a stopped tunnel, tall enough that nothing scrolls away.
func TestRenderDetailsInsights(t *testing.T) {
	inEachPalette(t, renderDetailsInsights)
}

func renderDetailsInsights(t *testing.T, suffix string) {
	wasAdmin := IsAdmin
	IsAdmin = true
	defer func() { IsAdmin = wasAdmin }()

	now := time.Now()
	office := tunnelEntry{tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStarted, health: manager.TunnelHealthConnected}
	office.config = sampleConfig("office", "10.8.0.2/24", 42*time.Second, 1331439862, 228589568)
	office.settings, office.settingsLoaded, office.probingAllowed = manager.TunnelSettings{Probe: true}, true, true
	office.path = manager.TunnelPath{TunnelMTU: 1440, RoutesAllTraffic: true, Peers: []manager.PeerPath{
		{Endpoint: "vpn.example.com:51820", Address: netip.MustParseAddrPort("[2001:db8::7]:51820"), Carrier: "Wi-Fi", CarrierKind: manager.InterfaceKindWiFi, CarrierMTU: 1500, CoveredByTunnel: true},
	}}
	office.pathLoaded = true
	seconds := sampleSeries(now, 3600, time.Second, goodProbes)
	for i := range seconds {
		if i%600 > 560 {
			seconds[i].Health = manager.TunnelHealthNoConnection
		}
		if i%120 == 0 {
			seconds[i].Handshakes = 1
		}
	}
	finished := &tunnelDiagnosis{finished: now.Add(-20 * time.Second), steps: []manager.DiagnosisStep{
		{ID: manager.DiagnosisEndpointResolves, Outcome: manager.DiagnosisPassed, Detail: "vpn.example.com: 192.0.2.10 2001:db8::7 in 14.2 ms"},
		{ID: manager.DiagnosisHandshake, Outcome: manager.DiagnosisPassed, Detail: "latest 2026-03-10T11:59:18Z, 42 s ago"},
		{ID: manager.DiagnosisPing, Outcome: manager.DiagnosisPassed, Detail: "10.8.0.1: 3 sent, 3 answered, average 21.4 ms"},
		{ID: manager.DiagnosisDNS, Outcome: manager.DiagnosisFailed, Detail: "10.8.0.1: no answer in 2s"},
		{ID: manager.DiagnosisEndpointRoute, Outcome: manager.DiagnosisPassed, Detail: "[2001:db8::7]:51820: via Wi-Fi (wifi, MTU 1500), tunnel routes cover it"},
		{ID: "future-step", Outcome: manager.DiagnosisSkipped, Detail: "raw detail of a step this version does not know"},
	}}
	running := &tunnelDiagnosis{running: true, steps: finished.steps[:2]}
	stopped := tunnelEntry{tunnel: manager.Tunnel{Name: "backup-site"}, state: manager.TunnelStopped}
	for _, c := range []struct {
		name      string
		entry     tunnelEntry
		diagnosis *tunnelDiagnosis
		r         chartRange
	}{
		{"details-insights", office, finished, rangeHour},
		{"details-testing", office, running, rangeMinute},
		{"details-stopped", stopped, nil, rangeMinute},
	} {
		mtw := &ManageTunnelsWindow{screen: screenDetails, detailsName: c.entry.tunnel.Name, timeRange: c.r, model: &appModel{
			entries: []tunnelEntry{c.entry}, globalState: manager.TunnelStarted,
			samples:   map[string]tunnelSamples{"office": {seconds: seconds}},
			diagnoses: map[string]*tunnelDiagnosis{c.entry.tunnel.Name: c.diagnosis},
		}}
		if c.diagnosis == nil {
			mtw.model.diagnoses = nil
		}
		s, img := renderScene(t, 524, 2600, 1, mtw.buildDetails)
		seen := make(map[string]bool)
		for _, hit := range s.hits {
			if hit.action != nil && seen[hit.id] {
				t.Errorf("%s: region %q twice", c.name, hit.id)
			}
			seen[hit.id] = true
		}
		if hit := s.hitByID("diagnostics-save"); hit == nil || hit.action == nil {
			t.Errorf("%s: no action to save diagnostics", c.name)
		}
		// Testing is offered only for an active tunnel that is not being tested already.
		canTest := c.entry.state == manager.TunnelStarted && (c.diagnosis == nil || !c.diagnosis.running)
		if hit := s.hitByID("diagnose"); (hit != nil && hit.action != nil) != canTest {
			t.Errorf("%s: test offered: %v, want %v", c.name, hit != nil, canTest)
		}
		if c.entry.state == manager.TunnelStarted && s.hitByID("chart:events") == nil {
			t.Errorf("%s: no events strip", c.name)
		}
		writePNG(t, c.name+suffix, img)
	}
}
