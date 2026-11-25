/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/manager"
)

func namedEntries(names ...string) []*tunnelEntry {
	entries := make([]*tunnelEntry, len(names))
	for i, name := range names {
		entries[i] = &tunnelEntry{tunnel: manager.Tunnel{Name: name}}
	}
	return entries
}

func entryNames(entries []*tunnelEntry) string {
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.tunnel.Name
	}
	return strings.Join(names, ",")
}

func TestFilterEntries(t *testing.T) {
	entries := namedEntries("Office-Berlin", "office-munich", "home", "Backup-Site", "lab-office")
	for _, c := range []struct {
		filter, want string
	}{
		{"", "Office-Berlin,office-munich,home,Backup-Site,lab-office"},
		{"   ", "Office-Berlin,office-munich,home,Backup-Site,lab-office"},
		{"office", "Office-Berlin,office-munich,lab-office"},
		{"OFFICE", "Office-Berlin,office-munich,lab-office"},
		{" berlin ", "Office-Berlin"},
		{"-", "Office-Berlin,office-munich,Backup-Site,lab-office"},
		{"site", "Backup-Site"},
		{"paris", ""},
	} {
		if got := entryNames(filterEntries(entries, c.filter)); got != c.want {
			t.Errorf("filter %q: got %q, want %q", c.filter, got, c.want)
		}
	}
}

func TestEditTyped(t *testing.T) {
	var pending uint16
	text := ""
	for _, unit := range []uint16{'o', 'f', 'f', '\b', 'x', '\r', '\t', 0x1B, ' ', 0xD83D, 0xDE00, 0xE9} {
		text, _, _ = editTyped(text, unit, &pending)
	}
	if text != "ofx \U0001F600é" {
		t.Errorf("got %q", text)
	}
	if _, changed, taken := editTyped("", '\b', &pending); changed || !taken {
		t.Error("backspace on nothing")
	}
	if _, _, taken := editTyped("a", '\r', &pending); taken {
		t.Error("Enter was taken as text")
	}
	// A lone second half is dropped, and Backspace removes a whole character.
	if got, _, _ := editTyped("a", 0xDE00, &pending); got != "a" {
		t.Errorf("lone low surrogate: %q", got)
	}
	if got, _, _ := editTyped("a\U0001F600", '\b', &pending); got != "a" {
		t.Errorf("backspace over an emoji: %q", got)
	}
}

func TestSortEntriesFavoritesFirst(t *testing.T) {
	entries := []tunnelEntry{
		{tunnel: manager.Tunnel{Name: "delta"}},
		{tunnel: manager.Tunnel{Name: "alpha"}},
		{tunnel: manager.Tunnel{Name: "zulu"}, settings: manager.TunnelSettings{Favorite: true}},
		{tunnel: manager.Tunnel{Name: "charlie"}, settings: manager.TunnelSettings{Favorite: true}},
	}
	sortEntries(entries)
	var names []string
	for i := range entries {
		names = append(names, entries[i].tunnel.Name)
	}
	if got := strings.Join(names, ","); got != "charlie,zulu,alpha,delta" {
		t.Errorf("got %s", got)
	}
}

func TestTunnelColorsHaveNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, color := range manager.TunnelColors {
		name := tunnelColorName(color)
		if name == tunnelColorName("") || seen[name] {
			t.Errorf("color %q has no name of its own: %q", color, name)
		}
		seen[name] = true
	}
}

// identityEntries are many tunnels, some with colors and some favorites, as the model sorts them.
func identityEntries() []tunnelEntry {
	office := tunnelEntry{tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStarted, health: manager.TunnelHealthConnected}
	office.config = sampleConfig("office", "10.8.0.2/24", 42*time.Second, 1331439862, 228589568)
	office.settings, office.settingsLoaded, office.probingAllowed = manager.TunnelSettings{Color: "teal", Favorite: true}, true, true
	entries := []tunnelEntry{office}
	for i, name := range []string{"berlin-dc", "frankfurt-dc", "home", "lab", "london-dc", "munich-office", "paris-dc", "a-very-long-tunnel-name-that-does-not-fit", "zurich-dc"} {
		entry := tunnelEntry{tunnel: manager.Tunnel{Name: name}, state: manager.TunnelStopped, settingsLoaded: true}
		entry.settings.Color = manager.TunnelColors[i%len(manager.TunnelColors)]
		entry.settings.Favorite = name == "home" || name == "a-very-long-tunnel-name-that-does-not-fit"
		entries = append(entries, entry)
	}
	sortEntries(entries)
	return entries
}

// TestRenderIdentityAndFilter draws tunnels with colors and favorites, the filter field empty, focused and with
// text that matches and that does not, the tray popup with colors, and the settings panel of the details screen.
func TestRenderIdentityAndFilter(t *testing.T) {
	inEachPalette(t, func(t *testing.T, suffix string) {
		wasAdmin := IsAdmin
		IsAdmin = true
		defer func() { IsAdmin = wasAdmin }()

		mtw := &ManageTunnelsWindow{model: &appModel{entries: identityEntries(), globalState: manager.TunnelStarted}}
		s, img := renderScene(t, 524, 900, 1, mtw.buildStatus)
		if s.hitByID("filter") == nil {
			t.Error("no filter field for a long list")
		}
		order := s.focusOrder()
		for i, id := range order {
			if id == "filter" && (i+1 >= len(order) || !strings.HasPrefix(order[i+1], "row:")) {
				t.Errorf("the filter field is not followed by the list: %v", order)
			}
		}
		writePNG(t, "identity"+suffix, img)

		mtw.filter = "DC"
		s, img = renderSceneWith(t, 524, 900, 1, 0, "filter", func(s *scene, width, height float64) {
			s.focus, s.focused = "filter", true
			mtw.buildStatus(s, width, height)
		})
		if s.hitByID("row:berlin-dc") == nil || s.hitByID("row:home") != nil || s.hitByID("filter-clear") == nil {
			t.Error("the filter does not narrow the list")
		}
		writePNG(t, "filter-typed"+suffix, img)

		mtw.filter = "nowhere"
		_, img = renderScene(t, 524, 900, 1, mtw.buildStatus)
		writePNG(t, "filter-nothing"+suffix, img)

		mtw.filter = ""
		_, img = renderScene(t, trayPopupWidth, 0, 1, (&TrayPopup{mtw: mtw}).build)
		writePNG(t, "identity-tray"+suffix, img)

		// A list of eight or fewer has no filter.
		short := &ManageTunnelsWindow{model: &appModel{entries: identityEntries()[:filterMinTunnels], globalState: manager.TunnelStarted}}
		if s, _ := renderScene(t, 524, 900, 1, short.buildStatus); s.hitByID("filter") != nil {
			t.Error("a short list has a filter field")
		}

		mtw.screen, mtw.detailsName = screenDetails, "office"
		s, img = renderSceneWith(t, 524, 820, 1, 330, "color:teal", mtw.buildDetails)
		for _, id := range []string{"favorite", "color:none", "color:gray", "probe", "probe-target"} {
			if s.hitByID(id) == nil {
				t.Errorf("settings panel: no region %q", id)
			}
		}
		writePNG(t, "details-settings"+suffix, img)
		// At the narrowest window the swatches wrap.
		_, img = renderSceneWith(t, 440, 820, 1, 330, "", mtw.buildDetails)
		writePNG(t, "details-settings-narrow"+suffix, img)
	})
}
