// Package console is the launchpad's web page for the home network: set the
// outside address, invite devices, see media servers and paired devices.
//
// It listens on its own port (never the one forwarded on the router),
// answers only home-network addresses, and needs the console password. It
// is plain HTTP unless asked otherwise, so browsers don't warn about the
// launchpad's self-signed certificate.
package console

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/skip2/go-qrcode"

	"github.com/imush/minstrel-launchpad/internal/auth"
	"github.com/imush/minstrel-launchpad/internal/discovery"
	"github.com/imush/minstrel-launchpad/internal/lan"
	"github.com/imush/minstrel-launchpad/internal/satellite"
	"github.com/imush/minstrel-launchpad/internal/server"
	"github.com/imush/minstrel-launchpad/internal/settings"
	"github.com/imush/minstrel-satellite/tunnel"
)

//go:embed static
var static embed.FS

// Registry is the view of discovery the console needs.
type Registry interface {
	Servers() []discovery.Server
	Refresh()
	SetManual([]string)
}

// Console serves the page and its JSON API.
type Console struct {
	Version     string
	Fingerprint string
	Pairing     *server.Pairing
	Store       *auth.Store
	Registry    Registry
	Settings    *settings.File
	Access      *Access
	Limiter     *auth.Limiter
	Log         *slog.Logger

	// Satellite runs the link to a minstrel-satellite.
	Satellite *satellite.Manager

	// Set by flags or environment: shown, but not editable here.
	NameLocked, PublicLocked, ServersLocked, SatelliteLocked bool
	// TLS is set when the console is served over HTTPS.
	TLS bool

	mux *http.ServeMux
}

// Handler returns the console's HTTP handler.
func (c *Console) Handler() http.Handler {
	c.mux = http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	files := http.FileServerFS(sub)
	c.mux.Handle("GET /", files)
	c.mux.HandleFunc("GET /api/session", c.session)
	c.mux.HandleFunc("POST /api/setup", c.setup)
	c.mux.HandleFunc("POST /api/login", c.login)
	c.mux.HandleFunc("POST /api/logout", c.logout)
	c.mux.HandleFunc("GET /api/state", c.authed(c.state))
	c.mux.HandleFunc("PUT /api/settings", c.authed(c.saveSettings))
	c.mux.HandleFunc("POST /api/servers/refresh", c.authed(c.refresh))
	c.mux.HandleFunc("POST /api/invitations", c.authed(c.invite))
	c.mux.HandleFunc("DELETE /api/invitations/{id}", c.authed(c.cancel))
	c.mux.HandleFunc("DELETE /api/devices/{id}", c.authed(c.revoke))
	return http.HandlerFunc(c.serve)
}

func (c *Console) serve(w http.ResponseWriter, r *http.Request) {
	// Home network only, even if someone forwards this port by mistake.
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !lan.IsLAN(ap.Addr()) {
		http.Error(w, "the console is only available on the home network", http.StatusForbidden)
		return
	}
	// Only names a home network uses: a web page elsewhere can't point its
	// own domain at this address (DNS rebinding) and talk to the console.
	if !homeHost(r.Host) {
		http.Error(w, "open the console by the launchpad's IP address or local name", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	// Changes only from the console's own page.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if o := r.Header.Get("Origin"); o != "" && o != c.scheme()+"://"+r.Host {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
			return
		}
	}
	c.mux.ServeHTTP(w, r)
}

func (c *Console) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil || !c.Access.Valid(cookie.Value) {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (c *Console) session(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(cookieName)
	state := "login"
	switch {
	case cookie != nil && c.Access.Valid(cookie.Value):
		state = "ok"
	case !c.Access.HasPassword():
		state = "setup"
	}
	writeJSON(w, map[string]string{"state": state, "name": c.Pairing.Name()})
}

func (c *Console) setup(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	key := auth.Key(r.RemoteAddr)
	if c.Limiter.Blocked(key) {
		http.Error(w, "too many attempts; try again in 15 minutes", http.StatusTooManyRequests)
		return
	}
	id, err := c.Access.Setup(req.Code, req.Password)
	if errors.Is(err, errBadSetup) {
		c.Limiter.Fail(key)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	c.Log.Info("console password set", "client", key)
	c.setCookie(w, id)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Console) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if !readJSON(w, r, &req) {
		return
	}
	key := auth.Key(r.RemoteAddr)
	if c.Limiter.Blocked(key) {
		http.Error(w, "too many attempts; try again in 15 minutes", http.StatusTooManyRequests)
		return
	}
	id, err := c.Access.Login(req.Password)
	if err != nil {
		c.Limiter.Fail(key)
		c.Log.Info("console login failed", "client", key)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	c.setCookie(w, id)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		c.Access.Logout(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, Secure: c.TLS, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (c *Console) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		Secure: c.TLS, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (c *Console) scheme() string {
	if c.TLS {
		return "https"
	}
	return "http"
}

// homeHost reports whether a Host header names the launchpad the way a
// home network does: an IP address, localhost, a bare host name, or a
// local domain.
func homeHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if host == "" || !validHostname(host) {
		return false
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".localhost", ".fritz.box"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func (c *Console) state(w http.ResponseWriter, r *http.Request) {
	type device struct {
		auth.Device
		TokenHash string `json:"tokenHash,omitempty"`
	}
	devices := []device{}
	for _, d := range c.Store.Devices() {
		devices = append(devices, device{Device: d})
	}
	type invitation struct {
		ID      string    `json:"id"`
		Label   string    `json:"label,omitempty"`
		Created time.Time `json:"created"`
		Expires time.Time `json:"expires"`
	}
	invitations := []invitation{}
	for _, inv := range c.Store.Invitations() {
		invitations = append(invitations, invitation{inv.ID, inv.Label, inv.Created, inv.Expires})
	}
	set, err := c.Settings.Load()
	if err != nil {
		c.Log.Error("reading settings", "err", err)
	}
	servers := c.Registry.Servers()
	if servers == nil {
		servers = []discovery.Server{}
	}
	var lanAddrs []string
	for _, ifc := range lan.IPv4() {
		lanAddrs = append(lanAddrs, net.JoinHostPort(ifc.Addr.String(), c.Pairing.Port))
	}
	writeJSON(w, map[string]any{
		"name":            c.Pairing.Name(),
		"nameLocked":      c.NameLocked,
		"version":         c.Version,
		"fingerprint":     c.Fingerprint,
		"port":            c.Pairing.Port,
		"lan":             lanAddrs,
		"public":          nonNil(c.Pairing.Public()),
		"publicLocked":    c.PublicLocked,
		"satellite":       c.satelliteStatus(),
		"satelliteLocked": c.SatelliteLocked,
		"relays":          nonNil(c.Pairing.RelayAddresses()),
		"manual":          nonNil(set.Servers),
		"serversLocked":   c.ServersLocked,
		"servers":         servers,
		"devices":         devices,
		"invitations":     invitations,
	})
}

func (c *Console) saveSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    *string   `json:"name"`
		Public  *[]string `json:"public"`
		Servers *[]string `json:"servers"`
		// Satellite is a link to join, or "" to leave the satellite.
		Satellite *string `json:"satellite"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	set, err := c.Settings.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Name != nil {
		if c.NameLocked {
			http.Error(w, "the name is set by -name / LAUNCHPAD_NAME", http.StatusConflict)
			return
		}
		name, err := cleanName(*req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		set.Name = name
	}
	if req.Public != nil {
		if c.PublicLocked {
			http.Error(w, "the outside address is set by -public / LAUNCHPAD_PUBLIC", http.StatusConflict)
			return
		}
		public, err := cleanAddresses(*req.Public, c.Pairing.Port)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		set.Public = public
	}
	if req.Servers != nil {
		if c.ServersLocked {
			http.Error(w, "media servers are set by -servers / LAUNCHPAD_SERVERS", http.StatusConflict)
			return
		}
		servers, err := cleanServers(*req.Servers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		set.Servers = servers
	}
	if req.Satellite != nil {
		if c.SatelliteLocked {
			http.Error(w, "the satellite is set by -satellite / LAUNCHPAD_SATELLITE", http.StatusConflict)
			return
		}
		link := strings.TrimSpace(*req.Satellite)
		if link != "" {
			if _, err := tunnel.ParseLink(link); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		set.Satellite = link
	}
	if err := c.Settings.Save(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Name != nil {
		c.Pairing.SetName(set.Name)
		c.Log.Info("name changed", "name", set.Name)
	}
	if req.Public != nil {
		c.Pairing.SetPublic(set.Public)
		c.Log.Info("outside address changed", "public", strings.Join(set.Public, ","))
	}
	if req.Servers != nil {
		c.Registry.SetManual(set.Servers)
	}
	if req.Satellite != nil && c.Satellite != nil {
		_ = c.Satellite.Set(set.Satellite) // checked above
		if set.Satellite == "" {
			c.Log.Info("satellite removed")
		} else {
			c.Log.Info("satellite set", "satellite", c.Satellite.Status().Satellite)
		}
	}
	c.state(w, r)
}

func (c *Console) refresh(w http.ResponseWriter, r *http.Request) {
	c.Registry.Refresh()
	w.WriteHeader(http.StatusNoContent)
}

// How long invitations last: minutes to scan on the spot, days for a file
// sent to someone.
var validFor = map[string]time.Duration{
	"10m": 10 * time.Minute,
	"1d":  24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

func (c *Console) invite(w http.ResponseWriter, r *http.Request) {
	var req struct{ Label, Valid string }
	if !readJSON(w, r, &req) {
		return
	}
	ttl, ok := validFor[req.Valid]
	if !ok {
		ttl = validFor["10m"]
	}
	inv, err := c.Pairing.New(req.Label, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(inv.URI, qrcode.Medium, 512)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.Log.Info("invitation created", "id", inv.ID, "label", inv.Label, "expires", inv.Expires.Format(time.RFC3339))
	writeJSON(w, map[string]any{
		"id":        inv.ID,
		"label":     inv.Label,
		"uri":       inv.URI,
		"code":      inv.Code,
		"expires":   inv.Expires,
		"addresses": inv.Addresses,
		"qr":        "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		"file":      fileName(c.Pairing.Name(), inv.Label),
	})
}

func (c *Console) cancel(w http.ResponseWriter, r *http.Request) {
	ok, err := c.Store.Cancel(r.PathValue("id"))
	respond(w, ok, err)
}

func (c *Console) revoke(w http.ResponseWriter, r *http.Request) {
	ok, err := c.Store.Revoke(r.PathValue("id"))
	if ok {
		c.Log.Info("device revoked on the console", "id", r.PathValue("id"))
	}
	respond(w, ok, err)
}

func respond(w http.ResponseWriter, ok bool, err error) {
	switch {
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	case !ok:
		http.Error(w, "not found", http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// cleanAddresses checks host[:port] entries, adding the launchpad's port
// where none is given. A URL pasted in is reduced to its host and port.
func cleanAddresses(in []string, port string) ([]string, error) {
	out := []string{}
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if u, err := url.Parse(a); err == nil && u.Host != "" {
			a = u.Host
		}
		host, p, err := net.SplitHostPort(a)
		if err != nil {
			host, p = strings.Trim(a, "[]"), port
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q: the port must be a number from 1 to 65535", a)
		}
		if !validHostname(host) {
			return nil, fmt.Errorf("%q isn't a host name or IP address", a)
		}
		out = append(out, net.JoinHostPort(host, p))
	}
	return out, nil
}

func validHostname(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch == '-' || ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
				return false
			}
		}
	}
	return true
}

// cleanServers checks media server description URLs: http, on the LAN.
func cleanServers(in []string) ([]string, error) {
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "http" || u.Host == "" {
			return nil, fmt.Errorf("%q: give the server's description URL, like http://192.168.1.9:9791/…/desc.xml", s)
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !lan.IsLAN(ip) {
			return nil, fmt.Errorf("%q: use the server's home-network IP address", s)
		}
		out = append(out, s)
	}
	return out, nil
}

// cleanName checks a home's name: something short a person can read.
func cleanName(name string) (string, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "", errors.New("enter a name")
	}
	if utf8.RuneCountInString(name) > 40 {
		return "", errors.New("keep the name to 40 characters")
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", errors.New("the name has characters that can't be shown")
		}
	}
	return name, nil
}

// fileName names a pairing file after the home and who it's for.
func fileName(home, label string) string {
	clean := func(s string) string {
		return strings.Trim(strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
				return r
			case r == ' ' || r == '.':
				return '-'
			}
			return -1
		}, s), "-")
	}
	name := clean(home)
	if l := clean(label); l != "" {
		name += "-" + l
	}
	if name == "" {
		name = "home"
	}
	return name + ".minstrel"
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (c *Console) satelliteStatus() satellite.Status {
	if c.Satellite == nil {
		return satellite.Status{}
	}
	return c.Satellite.Status()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
