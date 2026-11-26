/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	testTunnelLUID   winipcfg.LUID = 100
	testWiFiLUID     winipcfg.LUID = 200
	testEthernetLUID winipcfg.LUID = 300
	testDownLUID     winipcfg.LUID = 400
)

// testRouteTables is a computer with Wi-Fi and Ethernet, both with a default route, Ethernet preferred by its
// metric, an adapter that is down, and a full tunnel.
func testRouteTables() *routeTables {
	return &routeTables{
		routes: []routeEntry{
			{testWiFiLUID, netip.MustParsePrefix("0.0.0.0/0"), 0},
			{testWiFiLUID, netip.MustParsePrefix("192.168.1.0/24"), 256},
			{testEthernetLUID, netip.MustParsePrefix("0.0.0.0/0"), 0},
			{testEthernetLUID, netip.MustParsePrefix("::/0"), 0},
			{testDownLUID, netip.MustParsePrefix("203.0.113.0/24"), 0},
			{testTunnelLUID, netip.MustParsePrefix("0.0.0.0/0"), 0},
			{testTunnelLUID, netip.MustParsePrefix("198.51.100.0/24"), 0},
		},
		ipInterfaces: map[ipInterfaceKey]ipInterfaceEntry{
			{testWiFiLUID, false}:     {metric: 50, mtu: 1500, connected: true},
			{testEthernetLUID, false}: {metric: 25, mtu: 1492, connected: true},
			{testEthernetLUID, true}:  {metric: 25, mtu: 1480, connected: true},
			{testDownLUID, false}:     {metric: 1, mtu: 1500, connected: false},
			{testTunnelLUID, false}:   {metric: 5, mtu: 1420, connected: true},
			{testTunnelLUID, true}:    {metric: 5, mtu: 1400, connected: true},
		},
		interfaces: map[winipcfg.LUID]interfaceEntry{
			testWiFiLUID:     {alias: "Wi-Fi", kind: InterfaceKindWiFi, mtu: 1500, operUp: true},
			testEthernetLUID: {alias: "Ethernet", kind: InterfaceKindEthernet, mtu: 1500, operUp: true},
			testDownLUID:     {alias: "Old adapter", kind: InterfaceKindEthernet, mtu: 1500, operUp: false},
			testTunnelLUID:   {alias: "office", kind: InterfaceKindOther, mtu: 65535, operUp: true},
		},
	}
}

func TestBestRoute(t *testing.T) {
	tables := testRouteTables()
	for _, c := range []struct {
		dest    string
		exclude winipcfg.LUID
		want    winipcfg.LUID
		found   bool
	}{
		// Ethernet's lower interface metric wins between the two default routes; the tunnel is left out.
		{"8.8.8.8", testTunnelLUID, testEthernetLUID, true},
		// Without leaving it out, the tunnel's default route has the lowest sum of metrics.
		{"8.8.8.8", 0, testTunnelLUID, true},
		// The longer prefix wins over a lower metric.
		{"192.168.1.20", testTunnelLUID, testWiFiLUID, true},
		// An interface that is not connected is not used, so the default route takes over.
		{"203.0.113.9", testTunnelLUID, testEthernetLUID, true},
		{"2001:db8::1", testTunnelLUID, testEthernetLUID, true},
	} {
		route, found := tables.bestRoute(netip.MustParseAddr(c.dest), c.exclude)
		if found != c.found || route.luid != c.want {
			t.Errorf("%s without %d: got %d %v, want %d %v", c.dest, c.exclude, route.luid, found, c.want, c.found)
		}
	}
	onlyTunnel := &routeTables{routes: []routeEntry{{testTunnelLUID, netip.MustParsePrefix("::/0"), 0}}, ipInterfaces: tables.ipInterfaces, interfaces: tables.interfaces}
	if _, found := onlyTunnel.bestRoute(netip.MustParseAddr("2001:db8::1"), testTunnelLUID); found {
		t.Error("a route was found where only the tunnel has one")
	}
}

func TestInterfaceKindOf(t *testing.T) {
	for _, c := range []struct {
		ifType winipcfg.IfType
		medium winipcfg.NdisPhysicalMedium
		want   InterfaceKind
	}{
		{winipcfg.IfTypeEthernetCSMACD, winipcfg.NdisPhysicalMedium802_3, InterfaceKindEthernet},
		{winipcfg.IfTypeEthernetCSMACD, winipcfg.NdisPhysicalMediumUnspecified, InterfaceKindEthernet},
		{winipcfg.IfTypeIEEE80211, winipcfg.NdisPhysicalMediumNative802_11, InterfaceKindWiFi},
		// Wireless adapters that call themselves Ethernet are told apart by their medium.
		{winipcfg.IfTypeEthernetCSMACD, winipcfg.NdisPhysicalMediumNative802_11, InterfaceKindWiFi},
		{winipcfg.IfTypeWwanpp, winipcfg.NdisPhysicalMediumWirelessWan, InterfaceKindMobile},
		{winipcfg.IfTypeWwanpp2, winipcfg.NdisPhysicalMediumUnspecified, InterfaceKindMobile},
		{winipcfg.IfTypeEthernetCSMACD, winipcfg.NdisPhysicalMediumBluetooth, InterfaceKindOther},
		{winipcfg.IfTypePropVirtual, winipcfg.NdisPhysicalMediumUnspecified, InterfaceKindOther},
		{winipcfg.IfTypeSoftwareLoopback, winipcfg.NdisPhysicalMediumUnspecified, InterfaceKindOther},
	} {
		if got := interfaceKindOf(c.ifType, c.medium); got != c.want {
			t.Errorf("type %d, medium %d: got %d, want %d", c.ifType, c.medium, got, c.want)
		}
	}
}

func TestBuildTunnelPath(t *testing.T) {
	config := &conf.Config{Name: "office"}
	config.Peers = []conf.Peer{
		{PublicKey: conf.Key{1}, Endpoint: conf.Endpoint{Host: "vpn.example.com", Port: 51820}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{PublicKey: conf.Key{2}},
		{PublicKey: conf.Key{3}, Endpoint: conf.Endpoint{Host: "198.51.100.7", Port: 51820}},
		{PublicKey: conf.Key{4}, Endpoint: conf.Endpoint{Host: "2001:db8::7", Port: 443}},
		{PublicKey: conf.Key{5}, Endpoint: conf.Endpoint{Host: "gone.example.com", Port: 51820}},
	}
	peers := []driverPeer{
		{publicKey: [32]byte{4}, endpoint: netip.MustParseAddrPort("[2001:db8::7]:443")},
		{publicKey: [32]byte{1}, endpoint: netip.MustParseAddrPort("192.0.2.10:51820")},
		{publicKey: [32]byte{2}},
		{publicKey: [32]byte{3}, endpoint: netip.MustParseAddrPort("198.51.100.7:51820")},
		{publicKey: [32]byte{5}},
	}
	path := buildTunnelPath(config, peers, testTunnelLUID, testRouteTables())
	if path.TunnelMTU != 1420 || !path.RoutesAllTraffic || len(path.Peers) != 4 {
		t.Fatalf("path: %+v", path)
	}
	first := path.Peers[0]
	if first.Peer != 0 || first.Endpoint != "vpn.example.com:51820" || first.Address.String() != "192.0.2.10:51820" ||
		first.Carrier != "Ethernet" || first.CarrierKind != InterfaceKindEthernet || first.CarrierMTU != 1492 || first.NoRoute || !first.CoveredByTunnel || first.IPv6() {
		t.Errorf("first peer: %+v", first)
	}
	// The tunnel's /24 is more specific than the default route outside it.
	if third := path.Peers[1]; third.Peer != 2 || third.Carrier != "Ethernet" || !third.CoveredByTunnel {
		t.Errorf("third peer: %+v", third)
	}
	if fourth := path.Peers[2]; fourth.Peer != 3 || !fourth.IPv6() || fourth.CarrierMTU != 1480 || fourth.CoveredByTunnel {
		t.Errorf("fourth peer: %+v", fourth)
	}
	// A peer whose endpoint the driver does not report has no path.
	if fifth := path.Peers[3]; fifth.Peer != 4 || fifth.Address.IsValid() || !fifth.NoRoute {
		t.Errorf("fifth peer: %+v", fifth)
	}
}
