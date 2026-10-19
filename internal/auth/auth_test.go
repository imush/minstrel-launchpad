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
	code, inv, err := s.Invite("Anna's iPad", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := s.Invite("", time.Hour)

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
