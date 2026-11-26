/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// Settings are a handful of fields. Refusing anything larger keeps a damaged or planted file from
	// costing more than a small read.
	maxTunnelSettingsSize = 4096

	// History holds at most a few hundred sessions and days per tunnel, which the manager keeps well below this
	// size; it checks that its worst case fits.
	MaxTunnelHistorySize = 512 * 1024
)

// A tunnelFileStore keeps one protected file per tunnel in a directory of its own under the data directory. The
// manager stores what it keeps about tunnels besides their configurations in such stores: settings and history.
type tunnelFileStore struct {
	directoryName string
	suffix        string
	maxSize       int
	tooLarge      string

	lock      sync.Mutex
	directory string
}

var (
	tunnelSettingsStore = &tunnelFileStore{directoryName: "Settings", suffix: ".json", maxSize: maxTunnelSettingsSize, tooLarge: "Tunnel settings file is too large"}
	tunnelHistoryStore  = &tunnelFileStore{directoryName: "History", suffix: ".json", maxSize: MaxTunnelHistorySize, tooLarge: "Tunnel history file is too large"}
)

// directoryPath creates the directory like the configurations directory: inside the data directory, whose
// protected ACL (SYSTEM and Administrators only) it inherits.
func (store *tunnelFileStore) directoryPath() (string, error) {
	store.lock.Lock()
	defer store.lock.Unlock()
	if store.directory != "" {
		return store.directory, nil
	}
	root, err := RootDirectory(true)
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, store.directoryName)
	err = os.Mkdir(c, os.ModeDir|0o700)
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	store.directory = c
	return store.directory, nil
}

// forgetDirectory makes the next use find the directory again, for tests that move the data directory.
func (store *tunnelFileStore) forgetDirectory() {
	store.lock.Lock()
	store.directory = ""
	store.lock.Unlock()
}

func (store *tunnelFileStore) path(name string) (string, error) {
	if !TunnelNameIsValid(name) {
		return "", errors.New("Tunnel name is not valid")
	}
	dir, err := store.directoryPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+store.suffix), nil
}

// load returns the file of a tunnel. The error satisfies os.IsNotExist when the tunnel has none.
func (store *tunnelFileStore) load(name string) ([]byte, error) {
	path, err := store.path(name)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, int64(store.maxSize)+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > store.maxSize {
		return nil, errors.New(store.tooLarge)
	}
	return contents, nil
}

// save replaces the file of a tunnel. It is written like a configuration file: to a temporary file with a
// protected ACL that only SYSTEM can read, then renamed into place.
func (store *tunnelFileStore) save(name string, contents []byte) error {
	if len(contents) > store.maxSize {
		return errors.New(store.tooLarge)
	}
	path, err := store.path(name)
	if err != nil {
		return err
	}
	return writeLockedDownFile(path, true, contents)
}

func (store *tunnelFileStore) delete(name string) error {
	path, err := store.path(name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// names returns the names of the tunnels that have a file in the store.
func (store *tunnelFileStore) names() ([]string, error) {
	dir, err := store.directoryPath()
	if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, file := range files {
		if !file.Type().IsRegular() || !strings.HasSuffix(file.Name(), store.suffix) {
			continue
		}
		name := strings.TrimSuffix(file.Name(), store.suffix)
		if !TunnelNameIsValid(name) {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

// LoadTunnelSettings returns the stored settings file of a tunnel. The error satisfies os.IsNotExist when the
// tunnel has none.
func LoadTunnelSettings(name string) ([]byte, error) {
	return tunnelSettingsStore.load(name)
}

// SaveTunnelSettings replaces the settings file of a tunnel.
func SaveTunnelSettings(name string, contents []byte) error {
	return tunnelSettingsStore.save(name, contents)
}

func DeleteTunnelSettings(name string) error {
	return tunnelSettingsStore.delete(name)
}

// ListTunnelSettingsNames returns the names of the tunnels that have a settings file.
func ListTunnelSettingsNames() ([]string, error) {
	return tunnelSettingsStore.names()
}

// LoadTunnelHistory returns the stored history file of a tunnel, at most MaxTunnelHistorySize bytes. The error
// satisfies os.IsNotExist when the tunnel has none.
func LoadTunnelHistory(name string) ([]byte, error) {
	return tunnelHistoryStore.load(name)
}

// SaveTunnelHistory replaces the history file of a tunnel. The history directory is protected like the
// configurations directory, since the history says when and from where the machine was connected.
func SaveTunnelHistory(name string, contents []byte) error {
	return tunnelHistoryStore.save(name, contents)
}

func DeleteTunnelHistory(name string) error {
	return tunnelHistoryStore.delete(name)
}

// ListTunnelHistoryNames returns the names of the tunnels that have a history file.
func ListTunnelHistoryNames() ([]string, error) {
	return tunnelHistoryStore.names()
}
