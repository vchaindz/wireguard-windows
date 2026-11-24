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
	"testing"
	"time"

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
	dpi := int(96*scale + 0.5)
	measureHDC := win.CreateCompatibleDC(0)
	defer win.DeleteDC(measureHDC)

	s := &scene{scroll: scroll}
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

	bitmap, err := walk.NewBitmapFromImageForDPI(s.rasterize(int(width*scale+0.5), int(height*scale+0.5), scale, themeBackdrop), dpi)
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

// TestRenderScreens draws every screen with sample tunnels in several states. Set WG_UI_RENDER_DIR
// to a directory to have the results written there as PNG files for looking at.
func TestRenderScreens(t *testing.T) {
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
	officeTraffic := &trafficHistory{}
	for i := 0; i < trafficHistoryLength; i++ {
		wave := float64((i*37)%23) / 23
		officeTraffic.samples = append(officeTraffic.samples, trafficSample{rx: 200000 + 900000*wave*wave, tx: 40000 + 250000*(1-wave)})
	}
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
		if name == "backup-site" {
			e.metrics = manager.TunnelMetrics{LastActiveEnd: time.Now().Add(-2 * time.Hour), LastActiveDuration: 35 * time.Minute}
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
		{"details", []tunnelEntry{stopped("backup-site"), conflict}, manager.TunnelStarted, "office", false},
	} {
		mtw := &ManageTunnelsWindow{model: &appModel{entries: c.entries, globalState: c.global, updateAvailable: c.update, traffic: map[string]*trafficHistory{"office": officeTraffic}}}
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
					file, err := os.Create(filepath.Join(dir, c.name+"-"+kind+map[float64]string{1: "", 1.5: "@150"}[scale]+".png"))
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
	writePNG(t, "focus-button", img)

	s, img = renderSceneWith(t, 524, 740, 1, 150, "toggle:site-05", mtw.buildStatus)
	if hit := s.hitByID("toggle:site-05"); hit == nil || !hit.clipped || hit.rect.y < hit.clip.y || hit.rect.y > hit.clip.y+hit.clip.h {
		t.Error("the focused switch is not inside the scrolled list")
	}
	writePNG(t, "focus-scrolled", img)

	s, img = renderSceneWith(t, trayPopupWidth, 0, 1, 0, "row:site-02", popup.build)
	if s.maxScroll <= 0 {
		t.Error("a long list of tunnels does not scroll in the tray popup")
	}
	writePNG(t, "focus-tray", img)

	s, img = renderScene(t, 524, logFiltersHeight, 1, mtw.buildLogFilters)
	order := s.focusOrder()
	if len(order) < 3 || order[0] != "all" || order[1] != "warnings" || order[2] != "tunnel:office" {
		t.Errorf("log filters: got %v", order)
	}
	writePNG(t, "log-filters", img)
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

func TestTrafficHistory(t *testing.T) {
	start := time.Unix(1700000000, 0)
	at := func(seconds float64) time.Time { return start.Add(time.Duration(seconds * float64(time.Second))) }
	var history trafficHistory
	if rate := history.current(); rate != (trafficSample{}) {
		t.Fatalf("rate without samples: %+v", rate)
	}
	// The first counters only set the baseline.
	history.record(at(0), 1000, 500)
	if len(history.samples) != 0 {
		t.Fatalf("%d samples after the baseline", len(history.samples))
	}
	history.record(at(2), 5000, 1500)
	if rate := history.current(); rate.rx != 2000 || rate.tx != 500 {
		t.Fatalf("got %+v, want 2000 in and 500 out per second", rate)
	}
	// A second reading right after is skipped, and its bytes count towards the next one.
	history.record(at(2.1), 5100, 1500)
	history.record(at(3), 6000, 1500)
	if rate := history.current(); len(history.samples) != 2 || rate.rx != 1000 || rate.tx != 0 {
		t.Fatalf("got %d samples, last %+v", len(history.samples), rate)
	}
	if peak := history.peak(); peak != 2000 {
		t.Fatalf("peak %v, want 2000", peak)
	}
	// Only the last minute is kept.
	for i := 0; i < 2*trafficHistoryLength; i++ {
		history.record(at(float64(4+i)), conf.Bytes(6000+100*(i+1)), 1500)
	}
	if len(history.samples) != trafficHistoryLength {
		t.Fatalf("%d samples kept, want %d", len(history.samples), trafficHistoryLength)
	}
	// Counters that go backwards mean a restarted tunnel: start over.
	history.record(at(1000), 10, 10)
	if len(history.samples) != 0 {
		t.Fatalf("%d samples after the counters went backwards", len(history.samples))
	}
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
