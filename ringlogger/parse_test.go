/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import "testing"

func TestParseLine(t *testing.T) {
	for _, c := range []struct {
		line string
		want ParsedLine
	}{
		{"[MGR] Starting WireGuard/0.6", ParsedLine{"MGR", "", LevelInfo, "Starting WireGuard/0.6"}},
		{"[TUN] [office] Startup complete", ParsedLine{"TUN", "office", LevelInfo, "Startup complete"}},
		{"[TUN] [office] Warning: the interface has Forwarding enabled", ParsedLine{"TUN", "office", LevelWarning, "the interface has Forwarding enabled"}},
		{"[MGR] [home-lab] Error: connection check: the network is cut off", ParsedLine{"MGR", "home-lab", LevelError, "connection check: the network is cut off"}},
		{"[MGR] Error: unable to create pipe: access denied", ParsedLine{"MGR", "", LevelError, "unable to create pipe: access denied"}},
		{"[GUI] Warning: something", ParsedLine{"GUI", "", LevelWarning, "something"}},
		// A level word later in the line is part of the message.
		{"[TUN] [office] cmd> Error: from a script", ParsedLine{"TUN", "office", LevelInfo, "cmd> Error: from a script"}},
		// Brackets that are not a tag stay in the message.
		{"[TUN] [office] [not a tag] text", ParsedLine{"TUN", "office", LevelInfo, "[not a tag] text"}},
		{"[MGR] [] text", ParsedLine{"MGR", "", LevelInfo, "[] text"}},
		{"no tags at all", ParsedLine{"", "", LevelInfo, "no tags at all"}},
		{"Warning: no tags", ParsedLine{"", "", LevelWarning, "no tags"}},
		{"", ParsedLine{}},
		{"[", ParsedLine{"", "", LevelInfo, "["}},
	} {
		if got := ParseLine(c.line); got != c.want {
			t.Errorf("%q: got %+v, want %+v", c.line, got, c.want)
		}
	}
}
