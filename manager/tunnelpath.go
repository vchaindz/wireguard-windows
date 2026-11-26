/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"net/netip"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// InterfaceKind is the kind of network a physical interface connects to, as far as it matters to a person
// looking at why a connection behaves as it does.
type InterfaceKind int

const (
	InterfaceKindOther InterfaceKind = iota
	InterfaceKindEthernet
	InterfaceKindWiFi
	InterfaceKindMobile
)

// PeerPath describes how the packets to one peer leave the computer.
type PeerPath struct {
	// Peer is the position of the peer in the tunnel's configuration.
	Peer int
	// Endpoint is the endpoint as configured, host and port.
	Endpoint string
	// Address is the endpoint the driver sends to: what the host name resolved to when the tunnel started, or
	// where the peer answered from since.
	Address netip.AddrPort
	// Carrier is the interface that the best route to Address outside the tunnel goes through, with its kind
	// and MTU. NoRoute is set, and these are empty, when there is no such route.
	Carrier     string
	CarrierKind InterfaceKind
	CarrierMTU  uint32
	NoRoute     bool
	// CoveredByTunnel is set when the tunnel's own routes are at least as specific as the route outside it.
	// WireGuardNT never sends its packets into its own interface, so this is not a loop by itself; it means the
	// packets to the endpoint follow a different path from other traffic to that address.
	CoveredByTunnel bool
}

// IPv6 reports whether the endpoint in use is an IPv6 address.
func (path *PeerPath) IPv6() bool {
	return path.Address.Addr().Is6() && !path.Address.Addr().Is4In6()
}

// TunnelPath is how a started tunnel reaches its peers.
type TunnelPath struct {
	// TunnelMTU is the largest packet the tunnel's interface takes, over its IPv4 and IPv6 sides.
	TunnelMTU uint32
	// RoutesAllTraffic is set when the tunnel takes over the default route of an address family.
	RoutesAllTraffic bool
	// Peers are the peers that have an endpoint, in the order of the configuration.
	Peers []PeerPath
}

// The overhead that WireGuard adds to each packet: the outer IP header (20 bytes for IPv4, 40 for IPv6), the UDP
// header (8), and WireGuard's own header and authentication tag (32).
const (
	WireGuardOverheadIPv4 = 60
	WireGuardOverheadIPv6 = 80
)

// A routeEntry is a row of a routing table, reduced to what choosing a route needs.
type routeEntry struct {
	luid   winipcfg.LUID
	prefix netip.Prefix
	metric uint32
}

// An ipInterfaceEntry is what an interface's IPv4 or IPv6 side adds to choosing a route: its metric, which
// Windows adds to the route's, its MTU, and whether it is connected.
type ipInterfaceEntry struct {
	metric    uint32
	mtu       uint32
	connected bool
}

type ipInterfaceKey struct {
	luid winipcfg.LUID
	ipv6 bool
}

// An interfaceEntry is what is shown about a network interface.
type interfaceEntry struct {
	alias  string
	kind   InterfaceKind
	mtu    uint32
	operUp bool
}

// routeTables is a copy of the routing state that choosing a route reads. It is filled from the system by
// readRouteTables and by hand in tests.
type routeTables struct {
	routes       []routeEntry
	ipInterfaces map[ipInterfaceKey]ipInterfaceEntry
	interfaces   map[winipcfg.LUID]interfaceEntry
}

// bestRoute chooses the route that Windows would use to reach dest, leaving out the interface exclude, which is the
// tunnel's own, and interfaces that are down: the longest matching prefix wins, and among equally long ones the
// lowest sum of route and interface metrics. This is also how WireGuardNT picks the route for its packets, so that
// they do not go back into the tunnel.
func (t *routeTables) bestRoute(dest netip.Addr, exclude winipcfg.LUID) (routeEntry, bool) {
	var best routeEntry
	bestMetric, found := uint64(0), false
	for _, route := range t.routes {
		if route.luid == exclude || !route.prefix.Contains(dest) {
			continue
		}
		ipInterface, ok := t.ipInterfaces[ipInterfaceKey{route.luid, dest.Is6()}]
		if !ok || !ipInterface.connected {
			continue
		}
		if iface, ok := t.interfaces[route.luid]; ok && !iface.operUp {
			continue
		}
		metric := uint64(route.metric) + uint64(ipInterface.metric)
		if !found || route.prefix.Bits() > best.prefix.Bits() || route.prefix.Bits() == best.prefix.Bits() && metric < bestMetric {
			best, bestMetric, found = route, metric, true
		}
	}
	return best, found
}

// tunnelCovers reports whether a route of the tunnel's own interface matches dest at least as specifically as
// the route outside it.
func (t *routeTables) tunnelCovers(dest netip.Addr, tunnel winipcfg.LUID, outside routeEntry, haveOutside bool) bool {
	for _, route := range t.routes {
		if route.luid == tunnel && route.prefix.Contains(dest) && (!haveOutside || route.prefix.Bits() >= outside.prefix.Bits()) {
			return true
		}
	}
	return false
}

// carrierMTU is the MTU of the interface for packets of a family: that of its IP side if known, else its own.
func (t *routeTables) carrierMTU(luid winipcfg.LUID, ipv6 bool) uint32 {
	if ipInterface, ok := t.ipInterfaces[ipInterfaceKey{luid, ipv6}]; ok && ipInterface.mtu > 0 {
		return ipInterface.mtu
	}
	return t.interfaces[luid].mtu
}

// tunnelMTU is the larger of the MTUs of the tunnel's IPv4 and IPv6 sides, or its interface MTU if it has neither.
func (t *routeTables) tunnelMTU(luid winipcfg.LUID) uint32 {
	mtu := uint32(0)
	for _, ipv6 := range []bool{false, true} {
		if ipInterface, ok := t.ipInterfaces[ipInterfaceKey{luid, ipv6}]; ok {
			mtu = max(mtu, ipInterface.mtu)
		}
	}
	if mtu == 0 {
		mtu = t.interfaces[luid].mtu
	}
	return mtu
}

// peerPath describes the path to one endpoint address.
func (t *routeTables) peerPath(address netip.AddrPort, tunnel winipcfg.LUID) PeerPath {
	path := PeerPath{Address: address}
	dest := address.Addr().Unmap()
	route, ok := t.bestRoute(dest, tunnel)
	path.CoveredByTunnel = t.tunnelCovers(dest, tunnel, route, ok)
	if !ok {
		path.NoRoute = true
		return path
	}
	iface := t.interfaces[route.luid]
	path.Carrier, path.CarrierKind = iface.alias, iface.kind
	path.CarrierMTU = t.carrierMTU(route.luid, dest.Is6())
	return path
}

// interfaceKindOf tells the kind of an interface from its type and its physical medium. Wireless adapters often
// call themselves Ethernet, which is why the medium is looked at first.
func interfaceKindOf(ifType winipcfg.IfType, medium winipcfg.NdisPhysicalMedium) InterfaceKind {
	switch medium {
	case winipcfg.NdisPhysicalMediumNative802_11, winipcfg.NdisPhysicalMediumWirelessLan:
		return InterfaceKindWiFi
	case winipcfg.NdisPhysicalMediumWirelessWan:
		return InterfaceKindMobile
	}
	switch ifType {
	case winipcfg.IfTypeIEEE80211:
		return InterfaceKindWiFi
	case winipcfg.IfTypeWwanpp, winipcfg.IfTypeWwanpp2:
		return InterfaceKindMobile
	case winipcfg.IfTypeEthernetCSMACD:
		if medium == winipcfg.NdisPhysicalMedium802_3 || medium == winipcfg.NdisPhysicalMediumUnspecified {
			return InterfaceKindEthernet
		}
	}
	return InterfaceKindOther
}

// readRouteTables copies the routing tables, the IP interfaces and the interfaces of both families. It only reads.
func readRouteTables() (*routeTables, error) {
	tables := &routeTables{
		ipInterfaces: make(map[ipInterfaceKey]ipInterfaceEntry),
		interfaces:   make(map[winipcfg.LUID]interfaceEntry),
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipv6 := family == windows.AF_INET6
		routes, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			return nil, err
		}
		for i := range routes {
			prefix := routes[i].DestinationPrefix.Prefix()
			if !prefix.IsValid() {
				continue
			}
			tables.routes = append(tables.routes, routeEntry{routes[i].InterfaceLUID, prefix, routes[i].Metric})
		}
		ipInterfaces, err := winipcfg.GetIPInterfaceTable(family)
		if err != nil {
			return nil, err
		}
		for i := range ipInterfaces {
			tables.ipInterfaces[ipInterfaceKey{ipInterfaces[i].InterfaceLUID, ipv6}] = ipInterfaceEntry{ipInterfaces[i].Metric, ipInterfaces[i].NLMTU, ipInterfaces[i].Connected}
		}
	}
	interfaces, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil {
		return nil, err
	}
	for i := range interfaces {
		row := &interfaces[i]
		tables.interfaces[row.InterfaceLUID] = interfaceEntry{row.Alias(), interfaceKindOf(row.Type, row.PhysicalMediumType), row.MTU, row.OperStatus == winipcfg.IfOperStatusUp}
	}
	return tables, nil
}

// tunnelStarted reports whether the manager tracks the tunnel as started, which is when its health monitor runs.
// It is asked before the driver adapter is opened, so that names a client makes up open nothing.
func tunnelStarted(tunnelName string) bool {
	trackedTunnelsLock.Lock()
	defer trackedTunnelsLock.Unlock()
	_, started := tunnelHealthMonitors[tunnelName]
	return started
}

// driverPeer is what the driver reports about a peer that matters for its path.
type driverPeer struct {
	publicKey [32]byte
	endpoint  netip.AddrPort // invalid if the peer has none
	handshake uint64         // FILETIME of the last handshake, 0 if none
}

// readDriverPeers reads the peers of a started tunnel from the driver, and the LUID of its interface.
func readDriverPeers(tunnelName string) ([]driverPeer, winipcfg.LUID, error) {
	driverAdapter, err := findDriverAdapter(tunnelName)
	if err != nil {
		return nil, 0, err
	}
	config, err := driverAdapter.Configuration()
	if err != nil {
		driverAdapter.Unlock()
		releaseDriverAdapter(tunnelName)
		return nil, 0, err
	}
	luid := driverAdapter.LUID()
	peers := make([]driverPeer, 0, config.PeerCount)
	peer := config.FirstPeer()
	for i := uint32(0); i < config.PeerCount; i++ {
		if i > 0 {
			peer = peer.NextPeer()
		}
		p := driverPeer{publicKey: peer.PublicKey, handshake: peer.LastHandshake}
		if peer.Flags&driver.PeerHasEndpoint != 0 {
			p.endpoint = peer.Endpoint.AddrPort()
		}
		peers = append(peers, p)
	}
	// The configuration lives in memory that the adapter's lock protects, so it is read completely first.
	driverAdapter.Unlock()
	return peers, luid, nil
}

// buildTunnelPath puts together the path of a tunnel from its configuration, the peers as the driver reports them,
// and the routing tables. It only reads, so that it can be tested with made-up tables.
func buildTunnelPath(config *conf.Config, peers []driverPeer, luid winipcfg.LUID, tables *routeTables) TunnelPath {
	path := TunnelPath{TunnelMTU: tables.tunnelMTU(luid), RoutesAllTraffic: config.RoutesAllTraffic()}
	for i := range config.Peers {
		configured := &config.Peers[i]
		if configured.Endpoint.IsEmpty() {
			continue
		}
		peerPath := PeerPath{NoRoute: true}
		for j := range peers {
			if peers[j].publicKey == configured.PublicKey && peers[j].endpoint.IsValid() {
				peerPath = tables.peerPath(peers[j].endpoint, luid)
				break
			}
		}
		peerPath.Peer, peerPath.Endpoint = i, configured.Endpoint.String()
		path.Peers = append(path.Peers, peerPath)
	}
	return path
}

// tunnelPath describes how a started tunnel reaches its peers. It is empty for a tunnel that is not started.
// Everything it looks at comes from the stored configuration, the driver and the system's tables.
func tunnelPath(tunnelName string) (TunnelPath, error) {
	if !tunnelStarted(tunnelName) {
		return TunnelPath{}, nil
	}
	config, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return TunnelPath{}, err
	}
	peers, luid, err := readDriverPeers(tunnelName)
	if err != nil {
		return TunnelPath{}, err
	}
	tables, err := readRouteTables()
	if err != nil {
		return TunnelPath{}, err
	}
	return buildTunnelPath(config, peers, luid, tables), nil
}
