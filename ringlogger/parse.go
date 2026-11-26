/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import "strings"

// A Level says how much attention a log line deserves.
type Level int

const (
	LevelInfo Level = iota
	LevelWarning
	LevelError
)

// A message that is a warning or an error says so with one of these prefixes. They are part of the
// text, so that a saved log reads the same as the one on screen, and are never translated.
const (
	WarningPrefix = "Warning: "
	ErrorPrefix   = "Error: "
)

// A ParsedLine is a log line taken apart.
type ParsedLine struct {
	// Source is the tag of the process that wrote the line: MGR, TUN or GUI.
	Source string
	// Tunnel is the name of the tunnel the line is about, or empty.
	Tunnel string
	Level  Level
	// Message is the line without tags and level prefix.
	Message string
}

// leadingTag splits off a "[tag] " at the beginning of a line.
func leadingTag(line string) (tag, rest string, ok bool) {
	if len(line) < 3 || line[0] != '[' {
		return "", line, false
	}
	end := strings.IndexByte(line, ']')
	if end < 2 || strings.ContainsAny(line[1:end], " [") {
		return "", line, false
	}
	return line[1:end], strings.TrimPrefix(line[end+1:], " "), true
}

// ParseLine takes a log line apart. A line looks like "[TUN] [office] Warning: something happened":
// the tag of the process, then for lines about a tunnel its name, then the level unless the line is
// merely informational.
func ParseLine(line string) (parsed ParsedLine) {
	rest := line
	if tag, after, ok := leadingTag(rest); ok {
		parsed.Source, rest = tag, after
		if tag, after, ok := leadingTag(rest); ok {
			parsed.Tunnel, rest = tag, after
		}
	}
	switch {
	case strings.HasPrefix(rest, ErrorPrefix):
		parsed.Level, rest = LevelError, rest[len(ErrorPrefix):]
	case strings.HasPrefix(rest, WarningPrefix):
		parsed.Level, rest = LevelWarning, rest[len(WarningPrefix):]
	}
	parsed.Message = rest
	return
}
