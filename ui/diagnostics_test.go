/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
)

// diagnosticsSample is a started tunnel with addresses in every part of the file: configuration, settings, path,
// test, history and log.
func diagnosticsSample(now time.Time) *diagnosticsInput {
	config := sampleConfig("office", "10.8.0.2/24", 42*time.Second, 1331439862, 228589568)
	config.Interface.Addresses = append(config.Interface.Addresses, netip.MustParsePrefix("fd00:8::2/64"))
	config.Interface.DNS = append(config.Interface.DNS, netip.MustParseAddr("fd00:8::1"))
	config.Interface.DNSSearch = []string{"corp.example.net"}
	config.Peers = append(config.Peers, conf.Peer{
		PublicKey:  *conf.NewPrivateKey(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")},
		Endpoint:   conf.Endpoint{Host: "2001:db8:5::7", Port: 443},
	})
	entry := tunnelEntry{
		tunnel: manager.Tunnel{Name: "office"}, state: manager.TunnelStarted, health: manager.TunnelHealthConnected,
		config:   config,
		settings: manager.TunnelSettings{Probe: true, ProbeTarget: "10.8.0.77", Color: "blue"}, settingsLoaded: true, probingAllowed: true,
		path: manager.TunnelPath{TunnelMTU: 1420, Peers: []manager.PeerPath{
			{Endpoint: "vpn.example.com:51820", Address: netip.MustParseAddrPort("192.0.2.10:51820"), Carrier: "Wi-Fi", CarrierKind: manager.InterfaceKindWiFi, CarrierMTU: 1500},
			{Peer: 1, Endpoint: "[2001:db8:5::7]:443", Address: netip.MustParseAddrPort("[2001:db8:5::7]:443"), Carrier: "Ethernet", CarrierMTU: 1500},
		}},
		pathLoaded:     true,
		historyLoaded:  true,
		historyEnabled: true,
		history: manager.TunnelHistory{Sessions: []manager.TunnelSession{
			{Start: now.Add(-3 * time.Hour), End: now.Add(-2 * time.Hour), ActiveSeconds: 3600, Endpoint: "old-vpn.example.com:51820", EndedBy: manager.SessionDeactivated},
			{Start: now.Add(-time.Hour), End: now, ActiveSeconds: 3600, Endpoint: "vpn.example.com:51820", EndedBy: manager.SessionInProgress},
		}},
	}
	diagnosis := &tunnelDiagnosis{finished: now, steps: []manager.DiagnosisStep{
		{ID: manager.DiagnosisEndpointResolves, Outcome: manager.DiagnosisPassed, Detail: "vpn.example.com: 192.0.2.10 2001:db8::10 in 12.0 ms"},
		{ID: manager.DiagnosisPing, Outcome: manager.DiagnosisPassed, Detail: "10.8.0.1: 3 sent, 3 answered, average 20.0 ms"},
		{ID: manager.DiagnosisDNS, Outcome: manager.DiagnosisFailed, Detail: "10.8.0.1: answered in 3.0 ms; fd00:8::1: no answer in 2s"},
	}}
	peerKey := config.Peers[0].PublicKey.String()
	logLines := []ringlogger.FollowLine{
		{Line: "[TUN] [office] Starting WireGuard/0.5.3 (Windows 10.0.26300; amd64)", Stamp: now},
		{Line: "[TUN] [office] Interface up; resolved vpn.example.com to 192.0.2.10", Stamp: now},
		{Line: "[TUN] [office] peer(" + peerKey + ") - Sending handshake initiation to [2001:db8:5::7]:443", Stamp: now},
		{Line: "[MGR] [office] Connection quality: measuring latency and loss to 10.8.0.77", Stamp: now},
		{Line: "[MGR] Update checker: no update, 15:04:05 and 2026-03-10T12:00:00Z are times", Stamp: now},
		{Line: "[MGR] [home] Starting another tunnel to 203.0.113.99", Stamp: now},
		{Line: "[TUN] Untagged tunnel service line", Stamp: now},
	}
	return &diagnosticsInput{
		now: now, appVersion: "0.5.3", driverVersion: "1.0", osName: "Windows 11 (build 26300)", arch: "amd64",
		entry:     entry,
		samples:   tunnelSamples{seconds: sampleSeries(now, 120, time.Second, goodProbes)},
		diagnosis: diagnosis,
		logLines:  logLines,
	}
}

// diagnosticsAddresses are every address and host name in the sample, in the spellings the file uses.
var diagnosticsAddresses = []string{
	"10.8.0.2", "10.8.0.1", "10.8.0.0", "10.8.0.77", "192.168.10.0", "172.20.0.0", "192.0.2.10",
	"fd00:8::2", "fd00:8::1", "2001:db8:5::7", "2001:db8::10",
	"vpn.example.com", "old-vpn.example.com", "corp.example.net",
}

func TestDiagnosticsRedaction(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	in := diagnosticsSample(now)
	text, hosts := collectDiagnostics(in)
	for _, address := range diagnosticsAddresses {
		if !strings.Contains(text, address) {
			t.Fatalf("the sample does not contain %q, so the test proves nothing about it", address)
		}
	}
	redacted := redactDiagnostics(text, hosts)
	for _, address := range diagnosticsAddresses {
		if strings.Contains(redacted, address) {
			t.Errorf("%q survived", address)
		}
	}
	// No address of any kind is left: whatever parses as one in the text is a placeholder now.
	for _, candidate := range regexp.MustCompile(`[0-9A-Fa-f:.]{7,}`).FindAllString(redacted, -1) {
		if addr, err := netip.ParseAddr(strings.Trim(candidate, ".:")); err == nil {
			t.Errorf("address %v survived", addr)
		}
	}
	// Lines of other tunnels, and tunnel lines without a name, are left out.
	if strings.Contains(text, "another tunnel") || strings.Contains(text, "Untagged tunnel") {
		t.Error("a line about something else was included")
	}
	// The same address gets the same placeholder everywhere: the endpoint in the path, the test and the log.
	endpointPlaceholder := regexp.MustCompile(`Address in use: (<address-\d+>):51820`).FindStringSubmatch(redacted)
	if endpointPlaceholder == nil {
		t.Fatalf("no placeholder for the endpoint in:\n%s", redacted)
	}
	if count := strings.Count(redacted, endpointPlaceholder[1]+":51820"); count < 1 || !strings.Contains(redacted, "to "+endpointPlaceholder[1]) {
		t.Errorf("placeholder %s not used consistently:\n%s", endpointPlaceholder[1], redacted)
	}
	hostPlaceholder := regexp.MustCompile(`Endpoint: (<host-\d+>):51820`).FindStringSubmatch(redacted)
	if hostPlaceholder == nil || !strings.Contains(redacted, "resolved "+hostPlaceholder[1]+" to") || !strings.Contains(redacted, hostPlaceholder[1]+": <address-") {
		t.Errorf("host placeholder not used consistently:\n%s", redacted)
	}
	// A name that only ends like a hidden one is a different name.
	if !strings.Contains(redacted, "endpoint <host-") || strings.Count(redacted, "old-<host") > 0 {
		t.Errorf("a longer name was hidden in parts:\n%s", redacted)
	}
	// Times and versions are not addresses.
	for _, kept := range []string{"15:04:05", "2026-03-10T12:00:00Z", "0.5.3", "10.0.26300"} {
		if !strings.Contains(redacted, kept) {
			t.Errorf("%q was taken for an address", kept)
		}
	}
	// Keys are shortened, in the file's own lines and in log lines, and private keys are never written.
	for i := range in.entry.config.Peers {
		key := in.entry.config.Peers[i].PublicKey.String()
		if strings.Contains(text, key) && strings.Contains(shortenKeys(text), key) {
			t.Errorf("public key %d is written in full", i+1)
		}
		if !strings.Contains(redacted, key[:8]+"…") {
			t.Errorf("public key %d is not shown shortened", i+1)
		}
	}
	privateKey := in.entry.config.Interface.PrivateKey.String()
	if strings.Contains(text, privateKey) || strings.Contains(text, privateKey[:8]) {
		t.Error("the private key is in the file")
	}
	if strings.Contains(text, in.entry.config.Interface.PrivateKey.Public().String()[:8]) {
		t.Error("the interface's public key is in the file")
	}

	// With addresses included, they stay, and keys are still shortened.
	included := shortenKeys(text)
	if !strings.Contains(included, "192.0.2.10") || !strings.Contains(included, "vpn.example.com") || strings.Contains(included, in.entry.config.Peers[0].PublicKey.String()) {
		t.Error("addresses included: wrong result")
	}
	writeTextFile(t, "diagnostics-redacted.txt", redacted)
}

// writeTextFile writes a text next to the renders, for looking at.
func writeTextFile(t *testing.T, name, text string) {
	dir := os.Getenv("WG_UI_RENDER_DIR")
	if len(dir) == 0 {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
