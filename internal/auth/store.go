// Package auth pairs app installs with the launchpad and checks their tokens.
//
// Pairing: the launchpad hands out a one-time code (in a QR code valid for
// minutes, or a pairing file valid for days). The app exchanges it for a
// long random token of its own, so a photo of a used QR code or an old file
// is useless and each device can be revoked alone. Only hashes of codes and
// tokens are kept.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const tokenPrefix = "mlp_"

// ErrBadCode is returned for unknown, used or expired pairing codes.
var ErrBadCode = errors.New("invalid or expired pairing code")

// Device is one paired app install.
type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"tokenHash"`
	Label     string    `json:"label,omitempty"` // from the invitation it was paired with
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"lastSeen,omitzero"`
	LastAddr  string    `json:"lastAddr,omitempty"` // IP it last connected from
}

// Invitation is a pairing code not yet used.
type Invitation struct {
	ID       string    `json:"id"`
	Label    string    `json:"label,omitempty"` // who it's for, shown on the console
	CodeHash string    `json:"codeHash"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
}

// Store keeps paired devices and pending invitations in a JSON file.
type Store struct {
	path string

	mu          sync.Mutex
	devices     []*Device
	invitations []*Invitation
	dirty       bool
}

type storeFile struct {
	Devices     []*Device     `json:"devices"`
	Invitations []*Invitation `json:"invitations,omitempty"`
}

// Open loads the store at path; a missing file is an empty store.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	s.devices = f.Devices
	s.invitations = f.Invitations
	return s, nil
}

// NewCode creates a one-time pairing code valid for ttl.
func (s *Store) NewCode(ttl time.Duration) (string, time.Time) {
	code, inv, _ := s.Invite("", ttl)
	return code, inv.Expires
}

// Invite creates a one-time pairing code valid for ttl, labelled with who
// it's for. Only its hash is kept, so the code can't be shown again.
func (s *Store) Invite(label string, ttl time.Duration) (string, Invitation, error) {
	code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random(16)))
	now := time.Now().UTC().Truncate(time.Second)
	inv := &Invitation{
		ID:       hex.EncodeToString(random(4)),
		Label:    cleanName(label, ""),
		CodeHash: hash(code),
		Created:  now,
		Expires:  time.Now().Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	s.invitations = append(s.invitations, inv)
	if err := s.save(); err != nil {
		s.invitations = s.invitations[:len(s.invitations)-1]
		return "", Invitation{}, err
	}
	return code, *inv, nil
}

// Invitations lists the unused, unexpired invitations, oldest first.
func (s *Store) Invitations() []Invitation {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	out := make([]Invitation, len(s.invitations))
	for i, inv := range s.invitations {
		out[i] = *inv
	}
	return out
}

// Cancel withdraws an invitation, reporting whether there was one.
func (s *Store) Cancel(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.invitations, func(inv *Invitation) bool { return inv.ID == id })
	if i < 0 {
		return false, nil
	}
	s.invitations = slices.Delete(s.invitations, i, i+1)
	return true, s.save()
}

// prune drops expired invitations; they're saved with the next change.
func (s *Store) prune() {
	now := time.Now()
	s.invitations = slices.DeleteFunc(s.invitations, func(inv *Invitation) bool { return now.After(inv.Expires) })
}

// Pair consumes code and registers a device, returning its token.
func (s *Store) Pair(code, name string) (string, Device, error) {
	h := []byte(hash(strings.ToLower(strings.TrimSpace(code))))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	i := slices.IndexFunc(s.invitations, func(inv *Invitation) bool {
		return subtle.ConstantTimeCompare([]byte(inv.CodeHash), h) == 1
	})
	if i < 0 {
		return "", Device{}, ErrBadCode
	}
	inv := s.invitations[i]
	s.invitations = slices.Delete(s.invitations, i, i+1)

	token := tokenPrefix + base64.RawURLEncoding.EncodeToString(random(32))
	d := &Device{
		ID:        hex.EncodeToString(random(4)),
		Name:      cleanName(name, "device"),
		Label:     inv.Label,
		TokenHash: hash(token),
		Created:   time.Now().UTC().Truncate(time.Second),
	}
	s.devices = append(s.devices, d)
	if err := s.save(); err != nil {
		s.devices = s.devices[:len(s.devices)-1]
		s.invitations = append(s.invitations, inv)
		return "", Device{}, err
	}
	return token, *d, nil
}

// Authenticate returns the device a token belongs to, noting when and from
// which IP it was last used.
func (s *Store) Authenticate(token, from string) (Device, bool) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return Device{}, false
	}
	h := []byte(hash(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if subtle.ConstantTimeCompare([]byte(d.TokenHash), h) == 1 {
			if now := time.Now().UTC(); now.Sub(d.LastSeen) > time.Minute {
				d.LastSeen = now.Truncate(time.Second)
				s.dirty = true
			}
			if from != "" && from != d.LastAddr {
				d.LastAddr = from
				s.dirty = true
			}
			return *d, true
		}
	}
	return Device{}, false
}

// Devices lists paired devices, oldest first.
func (s *Store) Devices() []Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Device, len(s.devices))
	for i, d := range s.devices {
		out[i] = *d
	}
	return out
}

// Revoke removes the device with id, reporting whether there was one.
func (s *Store) Revoke(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.devices, func(d *Device) bool { return d.ID == id })
	if i < 0 {
		return false, nil
	}
	s.devices = slices.Delete(s.devices, i, i+1)
	return true, s.save()
}

// Flush saves last-seen times, which are kept in memory between saves.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.save()
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(storeFile{s.devices, s.invitations}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

func hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails on supported platforms
	return b
}

func cleanName(name, def string) string {
	name = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	for utf8.RuneCountInString(name) > 64 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	if name == "" {
		return def
	}
	return name
}
