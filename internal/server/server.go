// Package server is the launchpad's HTTPS API: pairing, and the
// authenticated relay to home media servers.
//
//	POST /api/pair        {code, name} → {token, device}; the only open endpoint
//	GET  /api/info        launchpad name, version, addresses, and the media servers
//	POST /api/refresh     scan the LAN now
//	*    /u/<ip:port>/... relay to a media server, with URLs rewritten
//
// Requests without a token get a bare 404, so scanners learn nothing.
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/imush/minstrel-launchpad/internal/auth"
	"github.com/imush/minstrel-launchpad/internal/discovery"
	"github.com/imush/minstrel-launchpad/internal/rewrite"
)

// Bodies larger than this pass through unrewritten.
const maxRewrite = 32 << 20

// Error kinds in the X-Launchpad-Error header, so the app can say which
// link failed: the launchpad answered, but the server behind it did not.
const (
	errUnknownServer = "unknown-server"
	errUnreachable   = "server-unreachable"
)

// Registry is the view of discovery the handler needs.
type Registry interface {
	Servers() []discovery.Server
	Allowed(hostport string) bool
	Learn(hostport, from string) bool
	Refresh()
}

// Handler serves the public HTTPS API.
type Handler struct {
	Version   string
	Pairing   *Pairing
	Registry  Registry
	Store     *auth.Store
	Limiter   *auth.Limiter
	Log       *slog.Logger
	Transport http.RoundTripper
}

// NewTransport is the client side of the relay: LAN only, no proxies, no
// compression (bodies are rewritten as plain text).
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		DisableCompression:    true,
	}
}

var validHost = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$`)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !validHost.MatchString(r.Host) {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	key := auth.Key(r.RemoteAddr)
	if h.Limiter.Blocked(key) {
		w.Header().Set("Retry-After", "900")
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	if r.URL.Path == "/api/pair" {
		h.pair(w, r, key)
		return
	}

	header := r.Header.Get("Authorization")
	if header == "" {
		http.NotFound(w, r)
		return
	}
	token, ok := strings.CutPrefix(header, "Bearer ")
	dev, valid := h.Store.Authenticate(strings.TrimSpace(token), remoteIP(r))
	if !ok || !valid {
		h.Limiter.Fail(key)
		h.Log.Info("rejected token", "client", key)
		http.Error(w, "not paired", http.StatusUnauthorized)
		return
	}

	switch {
	case r.URL.Path == "/api/info" && r.Method == http.MethodGet:
		h.info(w, r, dev)
	case r.URL.Path == "/api/refresh" && r.Method == http.MethodPost:
		h.Registry.Refresh()
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/u/"):
		h.relay(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) pair(w http.ResponseWriter, r *http.Request, key string) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		h.Limiter.Fail(key)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token, dev, err := h.Store.Pair(req.Code, req.Name)
	if errors.Is(err, auth.ErrBadCode) {
		h.Limiter.Fail(key)
		h.Log.Info("rejected pairing code", "client", key)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err != nil {
		h.Log.Error("pairing failed", "err", err)
		http.Error(w, "pairing failed", http.StatusInternalServerError)
		return
	}
	h.Log.Info("paired", "device", dev.Name, "id", dev.ID, "client", key)
	writeJSON(w, map[string]any{
		"token":  token,
		"device": map[string]string{"id": dev.ID, "name": dev.Name},
		"name":   h.Pairing.Name(),
	})
}

func (h *Handler) info(w http.ResponseWriter, r *http.Request, dev auth.Device) {
	base := baseURL(r)
	keep := func(hp string) bool { return h.Registry.Allowed(hp) }
	type server struct {
		UDN          string `json:"udn"`
		Name         string `json:"name"`
		Manufacturer string `json:"manufacturer,omitempty"`
		Model        string `json:"model,omitempty"`
		Description  string `json:"description"`
		Icon         string `json:"icon,omitempty"`
	}
	servers := []server{}
	for _, s := range h.Registry.Servers() {
		servers = append(servers, server{
			UDN:          s.UDN,
			Name:         s.Name,
			Manufacturer: s.Manufacturer,
			Model:        s.Model,
			Description:  string(rewrite.ToClient([]byte(s.Location), base, keep)),
			Icon:         string(rewrite.ToClient([]byte(s.Icon), base, keep)),
		})
	}
	info := map[string]any{
		"name":    h.Pairing.Name(),
		"version": h.Version,
		"device":  map[string]string{"id": dev.ID, "name": dev.Name},
		"servers": servers,
	}
	// So the app follows when the outside address is changed on the console.
	if h.Pairing != nil {
		info["addresses"] = h.Pairing.Addresses()
	}
	writeJSON(w, info)
}

func (h *Handler) relay(w http.ResponseWriter, r *http.Request) {
	hostport, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/u/"), "/")
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil || !h.Registry.Allowed(ap.String()) {
		w.Header().Set("X-Launchpad-Error", errUnknownServer)
		http.NotFound(w, r)
		return
	}
	origin := ap.String()
	base := baseURL(r)
	keep := func(hp string) bool { return h.Registry.Allowed(hp) || h.Registry.Learn(hp, origin) }

	// Launchpad URLs the app sends (in SOAP arguments, say) go back to LAN form.
	if r.Body != nil && rewrite.Rewritable(r.Header.Get("Content-Type")) && r.ContentLength <= 1<<20 {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		body = rewrite.ToLAN(body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = origin
			pr.Out.URL.RawPath = "/" + rest
			pr.Out.URL.Path, _ = url.PathUnescape(pr.Out.URL.RawPath)
			pr.Out.Host = origin
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Accept-Encoding")
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("X-Minstrel-Base")
			rewrite.Headers(pr.Out.Header, rewrite.ToLAN)
		},
		Transport:     h.Transport,
		FlushInterval: -1, // stream audio as it arrives
		ModifyResponse: func(resp *http.Response) error {
			rewrite.Headers(resp.Header, func(v []byte) []byte { return rewrite.ToClient(v, base, keep) })
			resp.Header.Del("Set-Cookie")
			if r.Method == http.MethodHead || !rewrite.Rewritable(resp.Header.Get("Content-Type")) ||
				resp.Header.Get("Content-Encoding") != "" || resp.ContentLength > maxRewrite {
				return nil
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxRewrite+1))
			if err != nil {
				return err
			}
			if len(body) > maxRewrite {
				resp.Body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
				return nil
			}
			resp.Body.Close()
			body = rewrite.Body(body, base, origin, keep)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.Log.Debug("relay failed", "origin", origin, "err", err)
			w.Header().Set("X-Launchpad-Error", errUnreachable)
			http.Error(w, "media server not responding", http.StatusBadGateway)
		},
		ErrorLog: slog.NewLogLogger(h.Log.Handler(), slog.LevelDebug),
	}
	rp.ServeHTTP(w, r)
}

// The app's local proxy names the base it wants URLs rewritten to, such as
// http://127.0.0.1:47380/h/<home>, so it can pass responses through as is.
var validBase = regexp.MustCompile(`^https?://(127\.0\.0\.1|\[::1\]|localhost)(:\d{1,5})?(/[A-Za-z0-9._~-]+)*$`)

// baseURL is what LAN URLs are rewritten to for this request: the client's
// chosen base, or the address it reached the launchpad at.
func baseURL(r *http.Request) string {
	if b := r.Header.Get("X-Minstrel-Base"); b != "" && validBase.MatchString(b) {
		return b
	}
	return "https://" + r.Host
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func remoteIP(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return ap.Addr().Unmap().String()
}
