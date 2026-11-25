/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// useTemporaryRoot points the store at an empty directory for the duration of a test.
func useTemporaryRoot(t *testing.T) string {
	root := t.TempDir()
	savedRoot := cachedRootDir
	PresetRootDirectory(root)
	tunnelSettingsStore.forgetDirectory()
	tunnelHistoryStore.forgetDirectory()
	t.Cleanup(func() {
		cachedRootDir = savedRoot
		tunnelSettingsStore.forgetDirectory()
		tunnelHistoryStore.forgetDirectory()
	})
	return root
}

func TestTunnelHistoryStore(t *testing.T) {
	root := useTemporaryRoot(t)
	if _, err := LoadTunnelHistory("absent"); !os.IsNotExist(err) {
		t.Fatalf("missing file: got %v", err)
	}
	if info, err := os.Stat(filepath.Join(root, "History")); err != nil || !info.IsDir() {
		t.Fatalf("history directory not created: %v", err)
	}
	for _, name := range []string{"", "..", `..\Settings\x`, "a/b"} {
		if _, err := LoadTunnelHistory(name); err == nil || os.IsNotExist(err) {
			t.Errorf("load %q: got %v, want a name error", name, err)
		}
		if err := SaveTunnelHistory(name, []byte("{}")); err == nil {
			t.Errorf("save %q accepted", name)
		}
	}
	// A file at the cap is read; one byte more is refused, whatever it holds.
	exact := make([]byte, MaxTunnelHistorySize)
	if err := os.WriteFile(filepath.Join(root, "History", "exact.json"), exact, 0o600); err != nil {
		t.Fatal(err)
	}
	if contents, err := LoadTunnelHistory("exact"); err != nil || len(contents) != MaxTunnelHistorySize {
		t.Fatalf("file at the cap: %d bytes, %v", len(contents), err)
	}
	big := make([]byte, MaxTunnelHistorySize+1)
	if err := os.WriteFile(filepath.Join(root, "History", "big.json"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTunnelHistory("big"); err == nil {
		t.Fatal("oversized file accepted")
	}
	if err := SaveTunnelHistory("big", big); err == nil {
		t.Fatal("oversized history saved")
	}
	// Files that are not history, or whose names are not tunnel names, are not listed.
	os.WriteFile(filepath.Join(root, "History", "notes.txt"), nil, 0o600)
	os.Mkdir(filepath.Join(root, "History", "dir.json"), 0o700)
	names, err := ListTunnelHistoryNames()
	if err != nil || len(names) != 2 || names[0] != "big" || names[1] != "exact" {
		t.Fatalf("list: got %v, %v", names, err)
	}
	if err := DeleteTunnelHistory("big"); err != nil {
		t.Fatal(err)
	}
	// The settings store is separate.
	if names, _ := ListTunnelSettingsNames(); len(names) != 0 {
		t.Fatalf("settings list: got %v", names)
	}
}

func TestTunnelSettingsRejectsInvalidNames(t *testing.T) {
	useTemporaryRoot(t)
	for _, name := range []string{"", "..", `..\Configurations\x`, "a/b", "con", "x:y"} {
		if _, err := LoadTunnelSettings(name); err == nil || os.IsNotExist(err) {
			t.Errorf("load %q: got %v, want a name error", name, err)
		}
		if err := SaveTunnelSettings(name, []byte("{}")); err == nil {
			t.Errorf("save %q accepted", name)
		}
	}
}

func TestTunnelSettingsMissingAndOversized(t *testing.T) {
	root := useTemporaryRoot(t)
	if _, err := LoadTunnelSettings("absent"); !os.IsNotExist(err) {
		t.Fatalf("missing file: got %v", err)
	}
	if info, err := os.Stat(filepath.Join(root, "Settings")); err != nil || !info.IsDir() {
		t.Fatalf("settings directory not created: %v", err)
	}
	big := make([]byte, maxTunnelSettingsSize+1)
	if err := os.WriteFile(filepath.Join(root, "Settings", "big.json"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTunnelSettings("big"); err == nil {
		t.Fatal("oversized file accepted")
	}
	if err := SaveTunnelSettings("big", big); err == nil {
		t.Fatal("oversized settings saved")
	}
	names, err := ListTunnelSettingsNames()
	if err != nil || len(names) != 1 || names[0] != "big" {
		t.Fatalf("list: got %v, %v", names, err)
	}
}

// Saving sets SYSTEM as the owner of the file, which needs administrator rights, like saving a configuration.
func TestTunnelSettingsRoundTrip(t *testing.T) {
	useTemporaryRoot(t)
	err := SaveTunnelSettings("roundtrip", []byte(`{"Probe":true}`))
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_INVALID_OWNER) {
		t.Skipf("needs administrator rights: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	contents, err := LoadTunnelSettings("roundtrip")
	if err != nil || string(contents) != `{"Probe":true}` {
		t.Fatalf("load: got %q, %v", contents, err)
	}
	if err := DeleteTunnelSettings("roundtrip"); err != nil {
		t.Fatal(err)
	}
}
