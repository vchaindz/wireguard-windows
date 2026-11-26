/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"net/netip"
	"testing"
)

func TestRoutesAllTraffic(t *testing.T) {
	for _, c := range []struct {
		allowedIPs []string
		tableOff   bool
		want       bool
	}{
		{[]string{"10.0.0.0/8", "192.168.1.0/24"}, false, false},
		{[]string{"0.0.0.0/0"}, false, true},
		{[]string{"::/0"}, false, true},
		{[]string{"0.0.0.0/0"}, true, false},
		{[]string{"0.0.0.0/1"}, false, false},
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, false, true},
		{[]string{"::/1", "8000::/1"}, false, true},
		{[]string{"0.0.0.0/1", "8000::/1"}, false, false},
	} {
		config := Config{Interface: Interface{TableOff: c.tableOff}}
		// One allowed IP per peer, so that halves spread over peers are covered too.
		for _, allowedIP := range c.allowedIPs {
			config.Peers = append(config.Peers, Peer{AllowedIPs: []netip.Prefix{netip.MustParsePrefix(allowedIP)}})
		}
		if got := config.RoutesAllTraffic(); got != c.want {
			t.Errorf("%v, table off %v: got %v, want %v", c.allowedIPs, c.tableOff, got, c.want)
		}
	}
}
