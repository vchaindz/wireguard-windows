/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"encoding/json"
	"testing"
)

func TestTunnelSettingsColorValidation(t *testing.T) {
	for _, color := range append([]string{""}, TunnelColors[:]...) {
		if _, err := (TunnelSettings{Color: color}).validate(); err != nil {
			t.Errorf("color %q refused: %v", color, err)
		}
	}
	for _, color := range []string{"Green", "purple", " blue", "#ff0000"} {
		if _, err := (TunnelSettings{Color: color}).validate(); err == nil {
			t.Errorf("color %q accepted", color)
		}
	}
}

func TestTunnelSettingsParse(t *testing.T) {
	for _, c := range []struct {
		stored string
		want   TunnelSettings
		fails  bool
	}{
		// Written before colors and favorites existed.
		{`{"Probe":true,"ProbeTarget":"10.0.0.1"}`, TunnelSettings{Probe: true, ProbeTarget: "10.0.0.1"}, false},
		{`{"Probe":false,"ProbeTarget":"","Color":"teal","Favorite":true}`, TunnelSettings{Color: "teal", Favorite: true}, false},
		// A color of a newer version is dropped, and the rest is kept.
		{`{"Probe":true,"Color":"ultraviolet","Favorite":true}`, TunnelSettings{Probe: true, Favorite: true}, false},
		{`{"ProbeTarget":"not an address","Favorite":true}`, TunnelSettings{}, true},
		{`{`, TunnelSettings{}, true},
	} {
		got, err := parseTunnelSettings([]byte(c.stored))
		if (err != nil) != c.fails || got != c.want {
			t.Errorf("%s: got %+v, %v", c.stored, got, err)
		}
	}
	// What is written is read back the same.
	settings := TunnelSettings{Probe: true, ProbeTarget: "fd00::1", Color: "pink", Favorite: true}
	contents, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := parseTunnelSettings(contents); err != nil || got != settings {
		t.Errorf("round trip: got %+v, %v", got, err)
	}
}
