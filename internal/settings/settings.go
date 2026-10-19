// Package settings keeps what is set on the console, in settings.json in
// the data directory. Flags and environment variables, when given, win over
// it and lock the setting on the console.
package settings

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"
)

// Settings are the console-editable parts of the configuration.
type Settings struct {
	// Name is what the app calls this home.
	Name string `json:"name,omitempty"`
	// Public is where the app reaches the launchpad from outside the home:
	// host[:port] of a static IP or dynamic DNS name.
	Public []string `json:"public"`
	// Servers are description URLs of media servers discovery misses.
	Servers []string `json:"servers"`
}

// File is a settings file.
type File struct {
	path string
	mu   sync.Mutex
}

func Open(path string) *File { return &File{path: path} }

// Load reads the settings; a missing file gives empty settings.
func (f *File) Load() (Settings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var s Settings
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

func (f *File) Save(s Settings) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}
