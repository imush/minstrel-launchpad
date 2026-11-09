package server

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/imush/minstrel-launchpad/internal/auth"
	"github.com/imush/minstrel-launchpad/internal/lan"
)

// Pairing builds pairing invitations: a one-time code plus everything the
// app needs to find and trust this launchpad.
type Pairing struct {
	Fingerprint string
	Port        string // the port the launchpad listens on
	Store       *auth.Store
	// Relays lists where the home is reachable through a satellite.
	Relays func() []string

	mu     sync.RWMutex
	name   string
	public []string // host[:port] the app uses from outside the home
}

// SetName sets what the app calls this home.
func (p *Pairing) SetName(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.name = name
}

// Name is what the app calls this home.
func (p *Pairing) Name() string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.name
}

// SetPublic sets the addresses the app uses from outside the home.
func (p *Pairing) SetPublic(public []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.public = slices.Clone(public)
}

// Public returns the outside addresses as configured.
func (p *Pairing) Public() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Clone(p.public)
}

// Invitation is what the pairing QR code carries.
type Invitation struct {
	ID        string    `json:"id"`
	Label     string    `json:"label,omitempty"`
	URI       string    `json:"uri"`
	Code      string    `json:"code"`
	Expires   time.Time `json:"expires"`
	Addresses []string  `json:"addresses"`
	Relays    []string  `json:"relays,omitempty"`
}

// New creates an invitation valid for ttl, for the device or person label.
func (p *Pairing) New(label string, ttl time.Duration, opt auth.InviteOptions) (Invitation, error) {
	code, inv, err := p.Store.Invite(label, ttl, opt)
	if err != nil {
		return Invitation{}, err
	}
	addrs := p.Addresses()
	q := url.Values{}
	q.Set("v", "1")
	q.Set("n", p.Name())
	q.Set("fp", p.Fingerprint)
	q.Set("c", code)
	for _, a := range addrs {
		q.Add("a", a)
	}
	relays := p.RelayAddresses()
	for _, r := range relays {
		q.Add("r", r)
	}
	return Invitation{
		ID: inv.ID, Label: inv.Label, URI: "minstrel://pair?" + q.Encode(),
		Code: code, Expires: inv.Expires, Addresses: addrs, Relays: relays,
	}, nil
}

// RelayAddresses lists where the app can reach the launchpad through a
// satellite. The app tries them only when the direct addresses fail, since
// relayed traffic costs the satellite's owner.
func (p *Pairing) RelayAddresses() []string {
	if p == nil || p.Relays == nil {
		return nil
	}
	return p.Relays()
}

// Addresses lists where the app can reach the launchpad: the configured
// public addresses, then the LAN ones.
func (p *Pairing) Addresses() []string {
	var out []string
	for _, a := range p.Public() {
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(strings.Trim(a, "[]"), p.Port)
		}
		out = append(out, a)
	}
	for _, ifc := range lan.IPv4() {
		out = append(out, net.JoinHostPort(ifc.Addr.String(), p.Port))
	}
	// A global IPv6 address needs no NAT, so it may work from outside as
	// well as at home -- when the router lets it in. The app learns the
	// current list on every connection, so one that changes with the
	// prefix is picked up without anything to configure.
	for _, ifc := range lan.GlobalIPv6() {
		out = append(out, net.JoinHostPort(ifc.Addr.String(), p.Port))
	}
	return out
}

// Admin serves local management requests on a Unix socket in the data
// directory; only users who can read that directory can pair devices.
type Admin struct {
	Pairing     *Pairing
	Store       *auth.Store
	Registry    Registry
	Version     string
	Fingerprint string
	CurlPin     string
	// ConsoleLink makes a link for setting the console password.
	ConsoleLink func() (string, bool)
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/pair" && r.Method == http.MethodPost:
		inv, err := a.Pairing.New(r.URL.Query().Get("label"), 10*time.Minute, auth.InviteOptions{
			Share: r.URL.Query().Get("share") == "1",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, inv)
	case r.URL.Path == "/console-link" && r.Method == http.MethodPost:
		link, ok := a.ConsoleLink()
		if !ok {
			http.Error(w, "the console is off (-console off)", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"url": link})
	case r.URL.Path == "/devices" && r.Method == http.MethodGet:
		writeJSON(w, a.Store.Devices())
	case r.URL.Path == "/revoke" && r.Method == http.MethodPost:
		ok, err := a.Store.Revoke(r.URL.Query().Get("id"))
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		case !ok:
			http.Error(w, "no such device", http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	case r.URL.Path == "/share" && r.Method == http.MethodPost:
		ok, err := a.Store.SetShare(r.URL.Query().Get("id"), r.URL.Query().Get("on") == "1")
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		case !ok:
			http.Error(w, "no such device", http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	case r.URL.Path == "/label" && r.Method == http.MethodPost:
		ok, err := a.Store.SetLabel(r.URL.Query().Get("id"), r.URL.Query().Get("label"))
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		case !ok:
			http.Error(w, "no such device", http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	case r.URL.Path == "/video" && r.Method == http.MethodPost:
		ok, err := a.Store.SetVideoFor(r.URL.Query().Get("id"),
			auth.VideoReach(r.URL.Query().Get("reach")), "", r.URL.Query().Get("recursive") == "1")
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
		case !ok:
			http.Error(w, "no such device", http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	case r.URL.Path == "/status" && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{
			"name":        a.Pairing.Name(),
			"version":     a.Version,
			"fingerprint": a.Fingerprint,
			"curlPin":     a.CurlPin,
			"addresses":   a.Pairing.Addresses(),
			"relays":      a.Pairing.RelayAddresses(),
			"servers":     a.Registry.Servers(),
			"devices":     len(a.Store.Devices()),
		})
	default:
		http.NotFound(w, r)
	}
}

// ListenAdmin serves h on the Unix socket at path until ctx is done.
func ListenAdmin(ctx context.Context, path string, h http.Handler) error {
	_ = os.Remove(path) // left over from an unclean exit
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = os.Remove(path)
	}()
	go func() { _ = srv.Serve(ln) }()
	return nil
}
