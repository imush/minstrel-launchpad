package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/imush/minstrel-launchpad/internal/auth"
)

// pairWith pairs a device with an invitation made with opt, returning its
// token and id.
func pairWith(t *testing.T, h *Handler, opt auth.InviteOptions) (string, string) {
	t.Helper()
	code, _, err := h.Store.Invite("", time.Minute, opt)
	if err != nil {
		t.Fatal(err)
	}
	token, dev, err := h.Store.Pair(code, "device")
	if err != nil {
		t.Fatal(err)
	}
	return token, dev.ID
}

func TestSharing(t *testing.T) {
	h, _, _, listener := setup(t)
	h.Pairing = &Pairing{Fingerprint: "abc", Port: "8443", Store: h.Store}
	h.Pairing.SetPublic([]string{"home.example.net"})

	if rec := do(h, "POST", "/api/invitations", listener, `{"valid":"1d"}`, nil); rec.Code != 403 {
		t.Fatalf("listen-only device invited: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/devices", listener, "", nil); rec.Code != 403 {
		t.Fatalf("listen-only device listed devices: %d", rec.Code)
	}

	owner, ownerID := pairWith(t, h, auth.InviteOptions{Share: true})
	rec := do(h, "POST", "/api/invitations", owner, `{"label":"Anna","valid":"1h"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body)
	}
	var inv struct {
		ID, Code, QR string
		Expires      time.Time
		HomeOnly     bool
	}
	json.Unmarshal(rec.Body.Bytes(), &inv)
	if inv.Code == "" || inv.QR == "" || inv.HomeOnly || time.Until(inv.Expires) > time.Hour+time.Minute {
		t.Errorf("invitation %+v", inv)
	}

	// The guest can listen, but not invite in turn.
	token, guest, err := h.Store.Pair(inv.Code, "Anna's phone")
	if err != nil {
		t.Fatal(err)
	}
	if guest.Share || guest.InvitedBy != ownerID {
		t.Errorf("guest %+v", guest)
	}
	if rec := do(h, "POST", "/api/invitations", token, `{}`, nil); rec.Code != 403 {
		t.Errorf("guest invited: %d", rec.Code)
	}

	// The owner sees every device, and may revoke only the guest.
	rec = do(h, "GET", "/api/devices", owner, "", nil)
	var list []struct {
		ID         string
		Mine, Self bool
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 3 {
		t.Fatalf("devices %s", rec.Body)
	}
	for _, d := range list {
		if d.Mine != (d.ID == guest.ID) || d.Self != (d.ID == ownerID) {
			t.Errorf("device %+v", d)
		}
	}
	first := list[0].ID // paired from the console
	if rec := do(h, "DELETE", "/api/devices/"+first, owner, "", nil); rec.Code != 404 {
		t.Errorf("revoked a device it didn't invite: %d", rec.Code)
	}
	if rec := do(h, "DELETE", "/api/devices/"+guest.ID, owner, "", nil); rec.Code != 204 {
		t.Errorf("revoke guest: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/info", token, "", nil); rec.Code != 401 {
		t.Errorf("revoked guest still in: %d", rec.Code)
	}

	// Pending invitations: only its own, and it can cancel them.
	do(h, "POST", "/api/invitations", owner, `{"valid":"7d"}`, nil)
	h.Store.Invite("console", time.Minute, auth.InviteOptions{})
	rec = do(h, "GET", "/api/invitations", owner, "", nil)
	var pending []struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &pending)
	if len(pending) != 1 {
		t.Fatalf("pending %s", rec.Body)
	}
	if rec := do(h, "DELETE", "/api/invitations/"+pending[0].ID, owner, "", nil); rec.Code != 204 {
		t.Errorf("cancel: %d", rec.Code)
	}
	if n := len(h.Store.Invitations()); n != 1 {
		t.Errorf("%d invitations left, want the console's", n)
	}
}
