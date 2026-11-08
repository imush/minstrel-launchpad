// Package auth pairs app installs with the launchpad and checks their tokens.
//
// Pairing: the launchpad hands out a one-time code (in a QR code valid for
// minutes, or a pairing file valid for days). The app exchanges it for a
// long random token of its own, so a photo of a used QR code or an old file
// is useless and each device can be revoked alone. Only hashes of codes and
// tokens are kept.
//
// Devices either listen, or also share: a sharing device can invite others
// from the app while away from home. Those invitations only ever make
// listening devices, and a sharing device can revoke only the devices it
// invited; making a device a sharer is for the console, at home.
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
// VideoReach says how far from home a device may fetch video.
//
// Music and video are not the same cost. An album is tens of megabytes; a
// film is about a gigabyte an hour, and through a satellite every one of
// those bytes crosses a relay the launchpad's owner pays for. So the zero
// value — what a device gets when nobody has said otherwise — is the
// closed one.
type VideoReach string

const (
	// VideoHome: only while the device is on the home network.
	VideoHome VideoReach = ""
	// VideoDirect: also when it reaches the launchpad itself from outside.
	VideoDirect VideoReach = "direct"
	// VideoSatellite: also when the satellite is the only way in.
	VideoSatellite VideoReach = "satellite"
)

// Allows reports whether video may be served over a route.
func (v VideoReach) Allows(route Route) bool {
	switch route {
	case RouteHome:
		return true
	case RouteDirect:
		return v == VideoDirect || v == VideoSatellite
	default:
		return v == VideoSatellite
	}
}

// rank orders the settings so one can be capped by another.
func (v VideoReach) rank() int {
	switch v {
	case VideoDirect:
		return 1
	case VideoSatellite:
		return 2
	default:
		return 0
	}
}

// AtMost is v capped by max. Nobody can pass on more than they hold: a
// device allowed video only at home cannot invite someone who may watch
// through the satellite, whoever they are.
func (v VideoReach) AtMost(max VideoReach) VideoReach {
	if v.rank() > max.rank() {
		return max
	}
	return v
}

// Valid keeps an unknown string from quietly meaning "home only" when it
// was meant to grant something.
func (v VideoReach) Valid() bool {
	return v == VideoHome || v == VideoDirect || v == VideoSatellite
}

// Route is how a request reached the launchpad.
type Route int

const (
	// RouteHome: from the home network.
	RouteHome Route = iota
	// RouteDirect: from outside, straight to the launchpad.
	RouteDirect
	// RouteSatellite: from outside, through a relay.
	RouteSatellite
)

type Device struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	TokenHash string     `json:"tokenHash"`
	Label     string     `json:"label,omitempty"`     // from the invitation it was paired with
	Share     bool       `json:"share,omitempty"`     // may invite others from the app
	Video     VideoReach `json:"video,omitempty"`     // how far from home it may fetch video
	InvitedBy string     `json:"invitedBy,omitempty"` // the device whose invitation it used; empty for the console
	Created   time.Time  `json:"created"`
	LastSeen  time.Time  `json:"lastSeen,omitzero"`
	LastAddr  string     `json:"lastAddr,omitempty"` // IP it last connected from
}

// Invitation is a pairing code not yet used.
type Invitation struct {
	ID        string     `json:"id"`
	Label     string     `json:"label,omitempty"`     // who it's for, shown on the console
	Share     bool       `json:"share,omitempty"`     // the device paired with it may invite others
	Video     VideoReach `json:"video,omitempty"`     // video reach the paired device starts with
	InvitedBy string     `json:"invitedBy,omitempty"` // the device that made it; empty for the console
	CodeHash  string     `json:"codeHash"`
	Created   time.Time  `json:"created"`
	Expires   time.Time  `json:"expires"`
}

// InviteOptions say what an invitation grants and who made it.
type InviteOptions struct {
	Share     bool
	Video     VideoReach
	InvitedBy string
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
	code, inv, _ := s.Invite("", ttl, InviteOptions{})
	return code, inv.Expires
}

// Invite creates a one-time pairing code valid for ttl, labelled with who
// it's for. Only its hash is kept, so the code can't be shown again.
func (s *Store) Invite(label string, ttl time.Duration, opt InviteOptions) (string, Invitation, error) {
	code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random(16)))
	now := time.Now().UTC().Truncate(time.Second)
	inv := &Invitation{
		ID:        hex.EncodeToString(random(4)),
		Label:     cleanName(label, ""),
		Share:     opt.Share,
		Video:     opt.Video,
		InvitedBy: opt.InvitedBy,
		CodeHash:  hash(code),
		Created:   now,
		Expires:   time.Now().Add(ttl),
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
func (s *Store) Cancel(id string) (bool, error) { return s.cancel(id, nil) }

// CancelFor withdraws an invitation the device by made, reporting whether
// there was one.
func (s *Store) CancelFor(id, by string) (bool, error) { return s.cancel(id, &by) }

func (s *Store) cancel(id string, by *string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.invitations, func(inv *Invitation) bool {
		return inv.ID == id && (by == nil || inv.InvitedBy == *by)
	})
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
		Share:     inv.Share,
		Video:     inv.Video,
		InvitedBy: inv.InvitedBy,
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
func (s *Store) Revoke(id string) (bool, error) { return s.revoke(id, nil) }

// RevokeFor removes the device with id if the device by invited it,
// reporting whether there was one.
func (s *Store) RevokeFor(id, by string) (bool, error) { return s.revoke(id, &by) }

func (s *Store) revoke(id string, by *string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.devices, func(d *Device) bool {
		return d.ID == id && (by == nil || d.InvitedBy == *by)
	})
	if i < 0 {
		return false, nil
	}
	s.devices = slices.Delete(s.devices, i, i+1)
	return true, s.save()
}

// SetShare lets the device with id invite others, or stops it, reporting
// whether there was one.
func (s *Store) SetShare(id string, share bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.devices, func(d *Device) bool { return d.ID == id })
	if i < 0 {
		return false, nil
	}
	if s.devices[i].Share == share {
		return true, nil
	}
	s.devices[i].Share = share
	if err := s.save(); err != nil {
		s.devices[i].Share = !share
		return false, err
	}
	return true, nil
}

// SetVideo says how far from home a device may fetch video.
func (s *Store) SetVideo(id string, reach VideoReach) (bool, error) {
	if !reach.Valid() {
		return false, errors.New("unknown video setting")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.devices, func(d *Device) bool { return d.ID == id })
	if i < 0 {
		return false, nil
	}
	was := s.devices[i].Video
	if was == reach {
		return true, nil
	}
	s.devices[i].Video = reach
	if err := s.save(); err != nil {
		s.devices[i].Video = was
		return false, err
	}
	return true, nil
}

// SetVideoFor sets a device's video reach, and optionally that of every
// device invited through it.
//
// [by] is the device asking, or empty for the launchpad's owner on the
// console. A device may only change what it invited, directly or further
// down, and may not grant more than it holds itself — otherwise the first
// guest to be given the satellite could hand it to the world.
func (s *Store) SetVideoFor(id string, reach VideoReach, by string, recursive bool) (bool, error) {
	if !reach.Valid() {
		return false, errors.New("unknown video setting")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target := slices.IndexFunc(s.devices, func(d *Device) bool { return d.ID == id })
	if target < 0 {
		return false, nil
	}
	if by != "" {
		asker := slices.IndexFunc(s.devices, func(d *Device) bool { return d.ID == by })
		if asker < 0 || !s.invitedThrough(by, id) {
			return false, nil
		}
		reach = reach.AtMost(s.devices[asker].Video)
	}
	ids := map[string]bool{id: true}
	if recursive {
		for _, d := range s.devices {
			if s.invitedThrough(id, d.ID) {
				ids[d.ID] = true
			}
		}
	}
	was := map[string]VideoReach{}
	for _, d := range s.devices {
		if ids[d.ID] {
			was[d.ID] = d.Video
			d.Video = reach
		}
	}
	if err := s.save(); err != nil {
		for _, d := range s.devices {
			if old, ok := was[d.ID]; ok {
				d.Video = old
			}
		}
		return false, err
	}
	return true, nil
}

// invitedThrough reports whether [id] descends from [root] by invitation.
// Guards against a cycle in the stored data, which would otherwise hang.
func (s *Store) invitedThrough(root, id string) bool {
	for seen, cur := 0, id; cur != "" && seen < len(s.devices)+1; seen++ {
		i := slices.IndexFunc(s.devices, func(d *Device) bool { return d.ID == cur })
		if i < 0 {
			return false
		}
		if s.devices[i].InvitedBy == root {
			return true
		}
		cur = s.devices[i].InvitedBy
	}
	return false
}

// SetLabel says whose device this is. Devices report their own name at
// pairing ("iPhone", "Android phone"), which several of them share, so the
// label is what tells them apart. An empty label clears it.
func (s *Store) SetLabel(id, label string) (bool, error) {
	label = strings.TrimSpace(label)
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.devices, func(d *Device) bool { return d.ID == id })
	if i < 0 {
		return false, nil
	}
	was := s.devices[i].Label
	if was == label {
		return true, nil
	}
	s.devices[i].Label = label
	if err := s.save(); err != nil {
		s.devices[i].Label = was
		return false, err
	}
	return true, nil
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
