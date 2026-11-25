/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/manager"
)

func describeSegments(segments []timelineSegment, start time.Time) string {
	var parts []string
	for _, segment := range segments {
		parts = append(parts, fmt.Sprintf("%v-%v:%s", segment.start.Sub(start).Seconds(), segment.end.Sub(start).Seconds(), timelineStateKey(segment.state)))
	}
	return strings.Join(parts, " ")
}

func TestHealthSegments(t *testing.T) {
	start := time.Unix(1700000000, 0)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	sample := func(seconds int, health manager.TunnelHealth) manager.TunnelSample {
		return manager.TunnelSample{Time: at(seconds), Health: health}
	}
	const gap = 15 * time.Second
	for _, c := range []struct {
		name    string
		samples []manager.TunnelSample
		end     int
		want    string
	}{
		{"nothing", nil, 60, "0-60:no_data"},
		// Equal neighbours merge; the newest sample reaches to the end, which is close enough.
		{"steady", []manager.TunnelSample{sample(10, manager.TunnelHealthConnected), sample(15, manager.TunnelHealthConnected), sample(20, manager.TunnelHealthConnected)}, 30,
			"0-10:no_data 10-30:connected"},
		{"changes", []manager.TunnelSample{
			sample(0, manager.TunnelHealthUnverified), sample(5, manager.TunnelHealthConnected), sample(10, manager.TunnelHealthNoConnection),
			sample(15, manager.TunnelHealthNoConnection), sample(20, manager.TunnelHealthConnected),
		}, 25, "0-5:unverified 5-10:connected 10-20:no_connection 20-25:connected"},
		// A gap longer than allowed is no data; the sample before it covers a third of the allowed gap.
		{"gap", []manager.TunnelSample{sample(0, manager.TunnelHealthConnected), sample(40, manager.TunnelHealthConnected)}, 45,
			"0-5:connected 5-40:no_data 40-45:connected"},
		// Samples before the range only count for the part that reaches into it, and the end without fresh
		// samples is no data.
		{"clipped", []manager.TunnelSample{sample(-10, manager.TunnelHealthWaitingForPeer), sample(-2, manager.TunnelHealthNoConnectionNetworkBlocked)}, 60,
			"0-3:network_cut_off 3-60:no_data"},
		// Samples after the end are left out.
		{"after", []manager.TunnelSample{sample(0, manager.TunnelHealthConnected), sample(70, manager.TunnelHealthNoConnection)}, 60,
			"0-5:connected 5-60:no_data"},
	} {
		got := describeSegments(healthSegments(c.samples, start, at(c.end), gap), start)
		if got != c.want {
			t.Errorf("%s: got %s\nwant %s", c.name, got, c.want)
		}
	}
}

func TestTimelineColumns(t *testing.T) {
	start := time.Unix(1700000000, 0)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	segments := []timelineSegment{
		{at(0), at(30), timelineConnected},
		{at(30), at(31), timelineCutOff},
		{at(31), at(60), timelineConnected},
	}
	columns := timelineColumns(segments, start, time.Minute, 6)
	// A second of cut-off network stays visible in a column of ten seconds.
	want := []timelineState{timelineConnected, timelineConnected, timelineConnected, timelineCutOff, timelineConnected, timelineConnected}
	if fmt.Sprint(columns) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", columns, want)
	}
	if worst := worstStateBetween(segments, at(25), at(35)); worst != timelineCutOff {
		t.Errorf("worst between: %v", worst)
	}
}

func TestTimelineBuckets(t *testing.T) {
	start := time.Unix(1700000000, 0)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	samples := []manager.TunnelSample{
		{Time: at(1), Health: manager.TunnelHealthConnected, Handshakes: 1},
		{Time: at(6), Health: manager.TunnelHealthNoConnection, Probed: true, ProbesSent: 1, ProbesLost: 1},
		{Time: at(11), Health: manager.TunnelHealthConnected, Handshakes: 1, Unstable: true},
		// Too long after the last sample to count as a reconnect.
		{Time: at(31), Health: manager.TunnelHealthNoConnection},
		{Time: at(51), Health: manager.TunnelHealthConnected, ConflictSuspected: true},
	}
	buckets := timelineBuckets(samples, start, time.Minute, 6, 15*time.Second)
	if b := buckets[0]; b.handshakes != 1 || b.sent != 1 || b.lost != 1 || b.reconnects != 0 {
		t.Errorf("first bucket: %+v", b)
	}
	if b := buckets[1]; b.handshakes != 1 || b.reconnects != 1 || !b.unstable {
		t.Errorf("second bucket: %+v", b)
	}
	if b := buckets[5]; b.reconnects != 0 || !b.conflict {
		t.Errorf("last bucket: %+v", b)
	}
}

// A key used by two devices shows as handshakes every quarter of a minute and the warning bar, where a healthy
// connection renews every two minutes. The render makes both patterns visible next to each other.
func TestRenderTimeline(t *testing.T) {
	inEachPalette(t, renderTimeline)
}

func renderTimeline(t *testing.T, suffix string) {
	now := time.Now()
	flapping := sampleSeries(now, 3600, time.Second, nil)
	for i := range flapping {
		switch {
		case i%600 > 540:
			flapping[i].Health = manager.TunnelHealthNoConnection
		case i%600 > 520:
			flapping[i].Health = manager.TunnelHealthUnverified
		}
		if i%15 == 0 && i > 1800 {
			flapping[i].Handshakes = 1
			flapping[i].ConflictSuspected = i > 2000
		} else if i%120 == 0 {
			flapping[i].Handshakes = 1
		}
		if i%600 > 541 && i%600 < 560 {
			flapping[i].Unstable = true
		}
		if i%97 == 0 {
			flapping[i].Probed, flapping[i].ProbesSent, flapping[i].ProbesLost = true, 1, 1
		}
	}
	// The tunnel was off for a while.
	flapping = append(flapping[:1000], flapping[1300:]...)
	samples := tunnelSamples{seconds: flapping}
	for _, r := range []chartRange{rangeMinute, rangeHour} {
		build := func(s *scene, width, height float64) {
			s.fill(0, 0, width, height, 0, theme.backdrop)
			s.height = s.timeline("events", 16, 8, width-32, 48, samples, r, now) + 16
		}
		_, img := renderScene(t, 524, 0, 1, build)
		writePNG(t, "timeline-"+map[chartRange]string{rangeMinute: "minute", rangeHour: "hour"}[r]+suffix, img)
	}
	// The hover read-out names the state under the mouse.
	build := func(s *scene, width, height float64) {
		s.timeline("events", 16, 8, width-32, 48, samples, rangeHour, now)
		s.height = 200
	}
	s, img := renderSceneMouse(t, 524, 200, 1, 0, "", &[2]float64{400, 50}, build)
	found := false
	for _, text := range s.texts {
		if strings.Contains(text.text, " · ") && strings.Contains(text.text, ":") {
			found = true
		}
	}
	if !found {
		t.Error("no read-out under the mouse")
	}
	writePNG(t, "timeline-hover"+suffix, img)
}

func TestPathRows(t *testing.T) {
	if !mtuTooLarge(1440, 1500, true) || mtuTooLarge(1420, 1500, false) || mtuTooLarge(1420, 1500, true) || !mtuTooLarge(1441, 1500, false) || mtuTooLarge(0, 1500, false) || mtuTooLarge(1420, 0, false) {
		t.Error("mtuTooLarge")
	}
	path := &manager.TunnelPath{TunnelMTU: 1440, Peers: []manager.PeerPath{
		{Endpoint: "vpn.example.com:51820", Address: netip.MustParseAddrPort("[2001:db8::7]:51820"), Carrier: "Wi-Fi", CarrierKind: manager.InterfaceKindWiFi, CarrierMTU: 1500},
		{Peer: 1, Endpoint: "198.51.100.7:51820", Address: netip.MustParseAddrPort("198.51.100.9:51820"), NoRoute: true},
	}}
	diagnosis := &tunnelDiagnosis{steps: []manager.DiagnosisStep{{ID: manager.DiagnosisEndpointResolves, Detail: "vpn.example.com: 192.0.2.10 in 3.0 ms"}}}
	rows := pathRows(path, diagnosis)
	var lines []string
	for _, row := range rows {
		lines = append(lines, row.label+"="+row.value)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"Tunnel MTU=1440",
		"All traffic=No, only the allowed IPs",
		"Address in use=[2001:db8::7]:51820 (IPv6) · the name now resolves to other addresses; reactivate the tunnel to follow it",
		"Carried by=Wi-Fi\n",
		"Carrier MTU=1500 · the tunnel MTU plus 80 bytes of WireGuard does not fit; use a tunnel MTU of 1420 or less",
		"Address in use=198.51.100.9:51820 (IPv4) · the peer answered from another address than the configured one",
		"Carried by=no route outside the tunnel",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if rows[0].color != theme.amberSoft {
		t.Error("the tunnel MTU is not marked as too large")
	}
	// Without a test that resolved the name, nothing is said about it.
	if note := addressNote(&path.Peers[0], nil); note != "" {
		t.Errorf("note without a test: %q", note)
	}
}
