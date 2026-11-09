package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/imush/minstrel-launchpad/internal/auth"
)

// How long invitations made in the app last: minutes to scan on the spot,
// up to a week for a pairing file sent to someone.
var appValidFor = map[string]time.Duration{
	"10m": 10 * time.Minute,
	"1h":  time.Hour,
	"1d":  24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

// sharing serves the requests of devices that may invite others, from
// wherever the app reaches the launchpad:
//
//	GET    /api/devices            every paired device; mine marks those this device invited
//	DELETE /api/devices/<id>       revoke a device this device invited
//	PUT    /api/devices/<id>       {video, recursive} for a device it invited,
//	                               never granting more than this device holds
//	GET    /api/invitations        this device's invitations not yet used
//	POST   /api/invitations        {label, valid} → a listen-only invitation, with its QR code
//	DELETE /api/invitations/<id>   cancel one of this device's invitations
//
// It reports whether it handled the request.
func (h *Handler) sharing(w http.ResponseWriter, r *http.Request, dev auth.Device) bool {
	path := r.URL.Path
	if path != "/api/devices" && path != "/api/invitations" &&
		!strings.HasPrefix(path, "/api/devices/") && !strings.HasPrefix(path, "/api/invitations/") {
		return false
	}
	if !dev.Share {
		http.Error(w, "this device can't invite others; allow it on the launchpad's console", http.StatusForbidden)
		return true
	}
	switch {
	case path == "/api/devices" && r.Method == http.MethodGet:
		h.listDevices(w, dev)
	case path == "/api/invitations" && r.Method == http.MethodGet:
		h.listInvitations(w, dev)
	case path == "/api/invitations" && r.Method == http.MethodPost:
		h.invite(w, r, dev)
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/devices/"):
		h.setDeviceVideo(w, r, dev, strings.TrimPrefix(path, "/api/devices/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/devices/"):
		id := strings.TrimPrefix(path, "/api/devices/")
		ok, err := h.Store.RevokeFor(id, dev.ID)
		if ok {
			h.Log.Info("device revoked in the app", "id", id, "by", dev.ID)
		}
		respond(w, ok, err, "no device you invited has that id")
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/invitations/"):
		ok, err := h.Store.CancelFor(strings.TrimPrefix(path, "/api/invitations/"), dev.ID)
		respond(w, ok, err, "no invitation of yours has that id")
	default:
		http.NotFound(w, r)
	}
	return true
}

// setDeviceVideo lets a device change the video reach of one it invited.
//
// The store caps the grant at what this device holds, so nobody can pass
// on more than they were given: a guest allowed video only at home cannot
// hand the satellite to the next person down.
func (h *Handler) setDeviceVideo(w http.ResponseWriter, r *http.Request, dev auth.Device, id string) {
	var req struct {
		Video     string `json:"video"`
		Recursive bool   `json:"recursive"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	reach := auth.VideoReach(req.Video)
	if !reach.Valid() {
		http.Error(w, "video must be empty, direct or satellite", http.StatusBadRequest)
		return
	}
	ok, err := h.Store.SetVideoFor(id, reach, dev.ID, req.Recursive)
	if ok && err == nil {
		h.Log.Info("device video changed in the app",
			"id", id, "by", dev.ID, "asked", req.Video, "recursive", req.Recursive)
	}
	respond(w, ok, err, "no device you invited has that id")
}

func (h *Handler) listDevices(w http.ResponseWriter, dev auth.Device) {
	// Not the addresses devices connect from: those are for the console.
	type device struct {
		ID        string          `json:"id"`
		Name      string          `json:"name"`
		Label     string          `json:"label,omitempty"`
		Share     bool            `json:"share,omitempty"`
		Video     auth.VideoReach `json:"video,omitempty"`
		InvitedBy string          `json:"invitedBy,omitempty"`
		Created   time.Time       `json:"created"`
		LastSeen  time.Time       `json:"lastSeen,omitzero"`
		Mine      bool            `json:"mine,omitempty"` // invited by the asking device, so it may revoke it
		Self      bool            `json:"self,omitempty"`
	}
	out := []device{}
	for _, d := range h.Store.Devices() {
		out = append(out, device{
			ID: d.ID, Name: d.Name, Label: d.Label, Share: d.Share, Video: d.Video,
			InvitedBy: d.InvitedBy,
			Created:   d.Created, LastSeen: d.LastSeen,
			Mine: d.InvitedBy == dev.ID, Self: d.ID == dev.ID,
		})
	}
	writeJSON(w, out)
}

func (h *Handler) listInvitations(w http.ResponseWriter, dev auth.Device) {
	type invitation struct {
		ID      string    `json:"id"`
		Label   string    `json:"label,omitempty"`
		Created time.Time `json:"created"`
		Expires time.Time `json:"expires"`
	}
	out := []invitation{}
	for _, inv := range h.Store.Invitations() {
		if inv.InvitedBy == dev.ID {
			out = append(out, invitation{inv.ID, inv.Label, inv.Created, inv.Expires})
		}
	}
	writeJSON(w, out)
}

func (h *Handler) invite(w http.ResponseWriter, r *http.Request, dev auth.Device) {
	var req struct {
		Label string `json:"label"`
		Valid string `json:"valid"`
		Video string `json:"video"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ttl, ok := appValidFor[req.Valid]
	if !ok {
		ttl = appValidFor["1d"]
	}
	// Always listen-only: only the console makes devices that may invite.
	video := auth.VideoReach(req.Video)
	if !video.Valid() {
		http.Error(w, "video must be empty, direct or satellite", http.StatusBadRequest)
		return
	}
	inv, err := h.Pairing.New(req.Label, ttl,
		auth.InviteOptions{InvitedBy: dev.ID, Video: video.AtMost(dev.Video)})
	if err != nil {
		h.Log.Error("invitation failed", "err", err)
		http.Error(w, "invitation failed", http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(inv.URI, qrcode.Medium, 512)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("invitation created in the app", "id", inv.ID, "label", inv.Label, "by", dev.ID,
		"expires", inv.Expires.Format(time.RFC3339))
	writeJSON(w, map[string]any{
		"id":      inv.ID,
		"label":   inv.Label,
		"uri":     inv.URI,
		"code":    inv.Code,
		"expires": inv.Expires,
		"qr":      "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		// Without an outside address or satellite, it pairs at home only.
		"homeOnly": len(h.Pairing.Public()) == 0 && len(inv.Relays) == 0,
	})
}

func respond(w http.ResponseWriter, ok bool, err error, notFound string) {
	switch {
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	case !ok:
		http.Error(w, notFound, http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
