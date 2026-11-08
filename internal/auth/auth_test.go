package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPairing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := s.NewCode(time.Minute)
	token, dev, err := s.Pair(" "+strings.ToUpper(code)+" ", "Pixel\n7")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Name != "Pixel7" || !strings.HasPrefix(token, "mlp_") {
		t.Errorf("device %+v token %q", dev, token)
	}
	if _, _, err := s.Pair(code, "again"); !errors.Is(err, ErrBadCode) {
		t.Errorf("code reused: %v", err)
	}
	if d, ok := s.Authenticate(token, ""); !ok || d.ID != dev.ID {
		t.Errorf("token rejected")
	}
	if _, ok := s.Authenticate(token+"x", ""); ok {
		t.Errorf("wrong token accepted")
	}

	// Persisted, with the token only as a hash.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), token) || strings.Contains(string(raw), code) {
		t.Errorf("secret stored in clear: %s", raw)
	}
	s2, _ := Open(path)
	if _, ok := s2.Authenticate(token, ""); !ok {
		t.Errorf("token lost on reload")
	}
	if ok, _ := s2.Revoke(dev.ID); !ok {
		t.Fatal("revoke failed")
	}
	if _, ok := s2.Authenticate(token, ""); ok {
		t.Errorf("revoked token accepted")
	}
}

func TestExpiredCode(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "d.json"))
	code, _ := s.NewCode(-time.Second)
	if _, _, err := s.Pair(code, "x"); !errors.Is(err, ErrBadCode) {
		t.Errorf("expired code accepted: %v", err)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	for range l.MaxFailures - 1 {
		l.Fail("a")
	}
	if l.Blocked("a") {
		t.Fatal("blocked too early")
	}
	l.Fail("a")
	if !l.Blocked("a") || l.Blocked("b") {
		t.Errorf("blocking wrong client")
	}
}

func TestKey(t *testing.T) {
	if k := Key("[2001:db8:1:2:aaaa::1]:5555"); k != "2001:db8:1:2::/64" {
		t.Errorf("v6 key %q", k)
	}
	if Key("[2001:db8:1:2:bbbb::9]:1") != Key("[2001:db8:1:2:aaaa::1]:2") {
		t.Errorf("same /64 counted separately")
	}
	if k := Key("203.0.113.7:4444"); k != "203.0.113.7" {
		t.Errorf("v4 key %q", k)
	}
}

func TestInvitations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s, _ := Open(path)
	code, inv, err := s.Invite("Anna's iPad", 24*time.Hour, InviteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := s.Invite("", time.Hour, InviteOptions{})

	// Survives a restart, without the code in clear.
	s2, _ := Open(path)
	if got := s2.Invitations(); len(got) != 2 || got[0].Label != "Anna's iPad" {
		t.Fatalf("invitations %+v", got)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), code) {
		t.Errorf("code stored in clear")
	}
	token, dev, err := s2.Pair(code, "iPad")
	if err != nil || dev.Label != "Anna's iPad" {
		t.Fatalf("pair: %v %+v", err, dev)
	}
	if len(s2.Invitations()) != 1 {
		t.Errorf("used invitation still listed")
	}
	if d, _ := s2.Authenticate(token, "192.168.1.20"); d.LastAddr != "192.168.1.20" {
		t.Errorf("last address %q", d.LastAddr)
	}

	if ok, _ := s2.Cancel(inv.ID); ok {
		t.Errorf("cancelled a used invitation")
	}
	list := s2.Invitations()
	if ok, _ := s2.Cancel(list[0].ID); !ok {
		t.Fatal("cancel failed")
	}
	if _, _, err := s2.Pair(other, "x"); !errors.Is(err, ErrBadCode) {
		t.Errorf("cancelled code accepted: %v", err)
	}
}

func TestRenaming(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := s.NewCode(time.Minute)
	_, dev, err := s.Pair(code, "Android phone")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Label != "" {
		t.Errorf("unlabelled device starts with %q", dev.Label)
	}
	if ok, err := s.SetLabel(dev.ID, "  Sarah's phone  "); !ok || err != nil {
		t.Fatalf("set: %v %v", ok, err)
	}
	if got := s.Devices()[0]; got.Label != "Sarah's phone" || got.Name != "Android phone" {
		t.Errorf("after renaming: %+v", got)
	}

	// It is the point of the thing that it outlives a restart.
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Devices()[0].Label; got != "Sarah's phone" {
		t.Errorf("not saved: %q", got)
	}

	if ok, _ := again.SetLabel(dev.ID, ""); !ok {
		t.Errorf("clearing refused")
	}
	if got := again.Devices()[0].Label; got != "" {
		t.Errorf("not cleared: %q", got)
	}
	if ok, err := again.SetLabel("nosuchdevice", "x"); ok || err != nil {
		t.Errorf("unknown device: %v %v", ok, err)
	}
}

// pairVia makes a device the way the launchpad does: an invitation
// carrying what it grants, then a pairing against it.
func pairVia(t *testing.T, s *Store, name, by string, reach VideoReach) Device {
	t.Helper()
	code, _, err := s.Invite("", time.Minute, InviteOptions{InvitedBy: by, Video: reach, Share: true})
	if err != nil {
		t.Fatal(err)
	}
	_, d, err := s.Pair(code, name)
	if err != nil {
		t.Fatal(err)
	}
	if d.Video != reach {
		t.Fatalf("%s paired with %q, not the invitation's %q", name, d.Video, reach)
	}
	if d.InvitedBy != by {
		t.Fatalf("%s invited by %q, not %q", name, d.InvitedBy, by)
	}
	return d
}

func TestVideoReachRules(t *testing.T) {
	if got := VideoSatellite.AtMost(VideoDirect); got != VideoDirect {
		t.Errorf("a device may pass on more than it holds: %q", got)
	}
	if got := VideoDirect.AtMost(VideoSatellite); got != VideoDirect {
		t.Errorf("capping lowered something it shouldn't: %q", got)
	}
	if got := VideoDirect.AtMost(VideoHome); got != VideoHome {
		t.Errorf("home-only device passed on %q", got)
	}
	for _, c := range []struct {
		reach VideoReach
		route Route
		want  bool
	}{
		{VideoHome, RouteHome, true},
		{VideoHome, RouteDirect, false},
		{VideoHome, RouteSatellite, false},
		{VideoDirect, RouteDirect, true},
		{VideoDirect, RouteSatellite, false},
		{VideoSatellite, RouteSatellite, true},
		{VideoSatellite, RouteHome, true},
	} {
		if got := c.reach.Allows(c.route); got != c.want {
			t.Errorf("%q over route %v: got %v", c.reach, c.route, got)
		}
	}
}

func TestSetVideoForDelegation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := pairVia(t, s, "owner phone", "", VideoDirect)
	guest := pairVia(t, s, "guest phone", owner.ID, VideoHome)
	sub := pairVia(t, s, "sub phone", guest.ID, VideoHome)
	stranger := pairVia(t, s, "stranger", "", VideoHome)

	reach := func(id string) VideoReach {
		for _, d := range s.Devices() {
			if d.ID == id {
				return d.Video
			}
		}
		return VideoReach("missing")
	}

	// Capped at the inviter's own: owner holds direct, so satellite is not
	// theirs to give.
	if ok, err := s.SetVideoFor(guest.ID, VideoSatellite, owner.ID, false); !ok || err != nil {
		t.Fatalf("grant: %v %v", ok, err)
	}
	if got := reach(guest.ID); got != VideoDirect {
		t.Errorf("guest got %q, which the owner does not hold", got)
	}

	// Not yours to change.
	if ok, _ := s.SetVideoFor(stranger.ID, VideoDirect, owner.ID, false); ok {
		t.Errorf("a device changed one it never invited")
	}

	// Recursive reaches the whole subtree.
	if ok, err := s.SetVideoFor(guest.ID, VideoDirect, "", true); !ok || err != nil {
		t.Fatalf("recursive: %v %v", ok, err)
	}
	if got := reach(sub.ID); got != VideoDirect {
		t.Errorf("sub-share not updated: %q", got)
	}

	// Without the flag it stops at the one named.
	if ok, _ := s.SetVideoFor(guest.ID, VideoHome, "", false); !ok {
		t.Fatal("set")
	}
	if got := reach(sub.ID); got != VideoDirect {
		t.Errorf("sub-share changed without the recursive flag: %q", got)
	}

	// And it survives a restart.
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range again.Devices() {
		if d.ID == guest.ID && d.Video != VideoHome {
			t.Errorf("not saved: %q", d.Video)
		}
	}
}
