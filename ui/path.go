/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// interfaceKindName is how the kind of a network interface is called.
func interfaceKindName(kind manager.InterfaceKind) string {
	switch kind {
	case manager.InterfaceKindEthernet:
		return l18n.Sprintf("Ethernet")
	case manager.InterfaceKindWiFi:
		return l18n.Sprintf("Wi-Fi")
	case manager.InterfaceKindMobile:
		return l18n.Sprintf("mobile network")
	}
	return l18n.Sprintf("other network")
}

// wireGuardOverhead is what WireGuard adds to each packet sent to an endpoint of the family.
func wireGuardOverhead(ipv6 bool) uint32 {
	if ipv6 {
		return manager.WireGuardOverheadIPv6
	}
	return manager.WireGuardOverheadIPv4
}

// mtuTooLarge reports whether the tunnel's packets, with WireGuard's overhead added, are larger than the carrying
// interface takes, so that they are fragmented or dropped. Unknown MTUs are not judged.
func mtuTooLarge(tunnelMTU, carrierMTU uint32, ipv6 bool) bool {
	return tunnelMTU > 0 && carrierMTU > wireGuardOverhead(ipv6) && tunnelMTU+wireGuardOverhead(ipv6) > carrierMTU
}

// resolvedAddresses finds what a host name resolved to in the details of the last test, which writes them as
// "host: address address in 12.3 ms". It returns false if the test did not resolve the name.
func resolvedAddresses(diagnosis *tunnelDiagnosis, host string) ([]netip.Addr, bool) {
	if diagnosis == nil {
		return nil, false
	}
	for _, step := range diagnosis.steps {
		if step.ID != manager.DiagnosisEndpointResolves || step.Outcome != manager.DiagnosisPassed {
			continue
		}
		for _, part := range strings.Split(step.Detail, "; ") {
			rest, ok := strings.CutPrefix(part, host+": ")
			if !ok {
				continue
			}
			var addrs []netip.Addr
			for _, field := range strings.Fields(rest) {
				if addr, err := netip.ParseAddr(field); err == nil {
					addrs = append(addrs, addr.Unmap())
				}
			}
			return addrs, true
		}
	}
	return nil, false
}

// addressNote says why the address in use may not be what the configuration leads one to expect: a configured
// address that differs means the peer answered from elsewhere; a host name that now resolves to other addresses
// means the name changed since the tunnel started, which the tunnel does not follow until it is restarted.
func addressNote(peer *manager.PeerPath, diagnosis *tunnelDiagnosis) string {
	if !peer.Address.IsValid() {
		return ""
	}
	inUse := peer.Address.Addr().Unmap()
	host := peer.Endpoint
	if hostPort, err := netip.ParseAddrPort(host); err == nil {
		if hostPort.Addr().Unmap() != inUse {
			return l18n.Sprintf("the peer answered from another address than the configured one")
		}
		return ""
	}
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	if resolved, ok := resolvedAddresses(diagnosis, host); ok && len(resolved) > 0 {
		for _, addr := range resolved {
			if addr == inUse {
				return ""
			}
		}
		return l18n.Sprintf("the name now resolves to other addresses; reactivate the tunnel to follow it")
	}
	return ""
}

// pathRows are the rows of the path card: the tunnel's MTU and whether it takes all traffic, then for each peer
// its endpoint, the address in use, the interface that carries it and that interface's MTU.
func pathRows(path *manager.TunnelPath, diagnosis *tunnelDiagnosis) []detailRow {
	tunnelTooLarge := false
	for i := range path.Peers {
		peer := &path.Peers[i]
		if !peer.NoRoute && mtuTooLarge(path.TunnelMTU, peer.CarrierMTU, peer.IPv6()) {
			tunnelTooLarge = true
		}
	}
	var rows []detailRow
	if path.TunnelMTU > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Tunnel MTU"), value: strconv.FormatUint(uint64(path.TunnelMTU), 10), color: warnIf(tunnelTooLarge)})
	}
	allTraffic := l18n.Sprintf("No, only the allowed IPs")
	if path.RoutesAllTraffic {
		allTraffic = l18n.Sprintf("Yes")
	}
	rows = append(rows, detailRow{label: l18n.Sprintf("All traffic"), value: allTraffic})
	for i := range path.Peers {
		peer := &path.Peers[i]
		rows = append(rows, detailRow{label: l18n.Sprintf("Endpoint"), value: peer.Endpoint})
		if !peer.Address.IsValid() {
			rows = append(rows, detailRow{label: l18n.Sprintf("Address in use"), value: l18n.Sprintf("none yet"), color: theme.textDim})
			continue
		}
		family := l18n.Sprintf("IPv4")
		if peer.IPv6() {
			family = l18n.Sprintf("IPv6")
		}
		inUse := l18n.Sprintf("%s (%s)", peer.Address.String(), family)
		color := rgb(0)
		if note := addressNote(peer, diagnosis); len(note) > 0 {
			inUse, color = l18n.Sprintf("%s · %s", inUse, note), theme.amberSoft
		}
		rows = append(rows, detailRow{label: l18n.Sprintf("Address in use"), value: inUse, color: color})
		if peer.NoRoute {
			rows = append(rows, detailRow{label: l18n.Sprintf("Carried by"), value: l18n.Sprintf("no route outside the tunnel"), color: theme.redSoft})
			continue
		}
		// An interface is often named after its kind, as "Wi-Fi" or "Ethernet" are; the kind is then not repeated.
		carrier := peer.Carrier
		if kind := interfaceKindName(peer.CarrierKind); !strings.EqualFold(carrier, kind) {
			carrier = l18n.Sprintf("%s · %s", carrier, kind)
		}
		rows = append(rows, detailRow{label: l18n.Sprintf("Carried by"), value: carrier})
		if peer.CarrierMTU > 0 {
			row := detailRow{label: l18n.Sprintf("Carrier MTU"), value: strconv.FormatUint(uint64(peer.CarrierMTU), 10)}
			if mtuTooLarge(path.TunnelMTU, peer.CarrierMTU, peer.IPv6()) {
				overhead := wireGuardOverhead(peer.IPv6())
				// The numbers are passed as text, so that they get no thousands separator, as MTUs are written elsewhere.
				row.value = l18n.Sprintf("%s · the tunnel MTU plus %d bytes of WireGuard does not fit; use a tunnel MTU of %s or less",
					strconv.FormatUint(uint64(peer.CarrierMTU), 10), overhead, strconv.FormatUint(uint64(peer.CarrierMTU-overhead), 10))
				row.color = theme.amberSoft
			}
			rows = append(rows, row)
		}
	}
	return rows
}
