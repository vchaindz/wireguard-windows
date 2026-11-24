/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

// WaitsForPeerBeforeRouting reports whether the tunnel service holds back routes, addresses, DNS and firewall
// rules until a peer has answered. It does so unless the administrator asked for the configuration to be applied
// at once, or no peer has an endpoint that could be contacted first.
func (config *Config) WaitsForPeerBeforeRouting() bool {
	if AdminBool("ApplyRoutesImmediately") {
		return false
	}
	for i := range config.Peers {
		if !config.Peers[i].Endpoint.IsEmpty() {
			return true
		}
	}
	return false
}

// RoutesAllTraffic reports whether the tunnel takes over the default route of an address family, either with a
// /0 allowed IP or with the two /1 halves that are commonly used in its place. While such a tunnel has no
// working peer, the machine has no usable network.
func (config *Config) RoutesAllTraffic() bool {
	if config.Interface.TableOff {
		return false
	}
	var halves4, halves6 [2]bool
	for i := range config.Peers {
		for _, allowedIP := range config.Peers[i].AllowedIPs {
			if allowedIP != allowedIP.Masked() {
				continue
			}
			switch allowedIP.Bits() {
			case 0:
				return true
			case 1:
				high := allowedIP.Addr().AsSlice()[0]&0x80 != 0
				half := 0
				if high {
					half = 1
				}
				if allowedIP.Addr().Is4() {
					halves4[half] = true
				} else {
					halves6[half] = true
				}
			}
		}
	}
	return (halves4[0] && halves4[1]) || (halves6[0] && halves6[1])
}
