/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/windows/conf"
)

// TunnelSettings are the choices made for a tunnel in this client that are not part of its configuration. They
// are kept apart from the configuration so that it stays a plain wg-quick file that other clients can read.
type TunnelSettings struct {
	Probe       bool   // measure latency and loss
	ProbeTarget string // IP address to ping; empty means choose automatically
	Color       string // one of TunnelColors, or empty for none
	Favorite    bool   // listed before the other tunnels
}

// TunnelColors are the names of the colors a tunnel can be marked with. The UI decides what each looks like, so
// that it can pick a shade that suits its light or dark background; the manager only keeps the name.
var TunnelColors = [...]string{"green", "blue", "violet", "amber", "red", "teal", "pink", "gray"}

func tunnelColorKnown(name string) bool {
	for _, color := range TunnelColors {
		if name == color {
			return true
		}
	}
	return false
}

// validate returns the settings in their stored form, or an error if the target is not an address or the color
// is not one of TunnelColors.
func (settings TunnelSettings) validate() (TunnelSettings, error) {
	if settings.Color != "" && !tunnelColorKnown(settings.Color) {
		return settings, errors.New("The color of a tunnel must be one of the offered colors")
	}
	settings.ProbeTarget = strings.TrimSpace(settings.ProbeTarget)
	if settings.ProbeTarget == "" {
		return settings, nil
	}
	addr, err := netip.ParseAddr(settings.ProbeTarget)
	if err != nil || !probeTargetUsable(addr) {
		return settings, errors.New("The address to measure must be a single IPv4 or IPv6 address")
	}
	settings.ProbeTarget = addr.Unmap().String()
	return settings, nil
}

// probingAllowed reports whether policy permits measuring connection quality at all.
func probingAllowed() bool {
	return !conf.AdminBool("DisableConnectionProbing")
}

// The settings are read from disk once per tunnel and then served from memory, because the health monitor
// asks for them on every sample. Only setTunnelSettings writes them, and it updates both.
var (
	tunnelSettingsLock  sync.Mutex
	tunnelSettingsCache = make(map[string]TunnelSettings)
)

// parseTunnelSettings reads stored settings. Fields that the file lacks, as in files written before they existed,
// keep their zero values. A color that this version does not know, as one written by a newer version, is dropped
// on its own, so that it does not take the other settings down with it.
func parseTunnelSettings(contents []byte) (TunnelSettings, error) {
	var settings TunnelSettings
	if err := json.Unmarshal(contents, &settings); err != nil {
		return TunnelSettings{}, err
	}
	if !tunnelColorKnown(settings.Color) {
		settings.Color = ""
	}
	settings, err := settings.validate()
	if err != nil {
		return TunnelSettings{}, err
	}
	return settings, nil
}

func loadTunnelSettings(tunnelName string) TunnelSettings {
	tunnelSettingsLock.Lock()
	defer tunnelSettingsLock.Unlock()
	if settings, found := tunnelSettingsCache[tunnelName]; found {
		return settings
	}
	var settings TunnelSettings
	contents, err := conf.LoadTunnelSettings(tunnelName)
	if err == nil {
		settings, err = parseTunnelSettings(contents)
	}
	if err != nil && !os.IsNotExist(err) {
		log.Printf("[%s] Warning: unable to read tunnel settings, using defaults: %v", tunnelName, err)
	}
	tunnelSettingsCache[tunnelName] = settings
	return settings
}

func setTunnelSettings(tunnelName string, settings TunnelSettings) error {
	if !conf.TunnelNameIsValid(tunnelName) {
		return errors.New("Tunnel name is not valid")
	}
	settings, err := settings.validate()
	if err != nil {
		return err
	}
	// Settings for a tunnel that does not exist would only be removed at the next start of the manager.
	if _, err := conf.LoadFromName(tunnelName); err != nil {
		return err
	}
	contents, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	tunnelSettingsLock.Lock()
	defer tunnelSettingsLock.Unlock()
	err = conf.SaveTunnelSettings(tunnelName, contents)
	if err != nil {
		return err
	}
	tunnelSettingsCache[tunnelName] = settings
	return nil
}

// removeOrphanedTunnelSettings deletes the settings of tunnels that no longer exist. It runs when the manager
// starts rather than when a tunnel is deleted, because editing a tunnel deletes it and creates it again under
// the same name, and its settings should survive that.
func removeOrphanedTunnelSettings() {
	removeOrphanedTunnelFiles(conf.ListTunnelSettingsNames, conf.DeleteTunnelSettings, "settings")
}

// removeOrphanedTunnelFiles deletes the files of a per-tunnel store whose tunnels no longer exist. what names the
// store in the log.
func removeOrphanedTunnelFiles(list func() ([]string, error), remove func(string) error, what string) {
	fileNames, err := list()
	if err != nil || len(fileNames) == 0 {
		return
	}
	configNames, err := conf.ListConfigNames()
	if err != nil {
		return
	}
	for _, name := range fileNames {
		found := false
		for _, configName := range configNames {
			// File names are compared the way the file system does.
			if strings.EqualFold(name, configName) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		if err := remove(name); err != nil {
			log.Printf("[%s] Warning: unable to remove %s of deleted tunnel: %v", name, what, err)
		}
	}
}
