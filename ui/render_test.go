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
)

// renderScene draws a scene the way a canvasView does, but into an image instead of a window.
func renderScene(t *testing.T, width, height, scale float64, build func(s *scene, width, height float64)) (*scene, image.Image) {
	dpi := int(96*scale + 0.5)
	measureHDC := win.CreateCompatibleDC(0)
	defer win.DeleteDC(measureHDC)

	s := &scene{}
	s.measure = func(text string, font themeFont, width float64) float64 {
		return measureWrapped(measureHDC, dpi, text, font, width)
	}
	build(s, width, height)
	if height == 0 {
		height = s.height
		s.shapes, s.texts, s.hits = nil, nil, nil
		build(s, width, height)
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
	unstable := connected
	unstable.unstable = true
	conflict := connected
	conflict.conflictSuspected = true
	waiting := entry("home-lab", manager.TunnelStarted, manager.TunnelHealthWaitingForPeer)
	waiting.config = sampleConfig("home-lab", "10.20.0.5/32", 0, 0, 1516)
	blocked := entry("customer-vpn", manager.TunnelStarted, manager.TunnelHealthNoConnectionNetworkBlocked)
	blocked.config = sampleConfig("customer-vpn", "172.16.4.9/32", 6*time.Minute, 52428800, 9437184)
	stopped := func(name string) tunnelEntry { return entry(name, manager.TunnelStopped, manager.TunnelHealthUnknown) }

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
		mtw := &ManageTunnelsWindow{model: &appModel{entries: c.entries, globalState: c.global, updateAvailable: c.update}}
		build := mtw.buildStatus
		if len(c.details) > 0 {
			mtw.screen, mtw.detailsName = screenDetails, c.details
			build = mtw.buildDetails
		}
		popup := &TrayPopup{mtw: mtw}
		for _, scale := range []float64{1, 1.5} {
			for kind, render := range map[string]func() (*scene, image.Image){
				"window": func() (*scene, image.Image) { return renderScene(t, 524, 740, scale, build) },
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
