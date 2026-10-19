// Package discovery finds the UPnP media servers on the home network and
// keeps the list of LAN origins the launchpad may relay to.
package discovery

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/imush/minstrel-launchpad/internal/lan"
)

const (
	searchTarget = "urn:schemas-upnp-org:device:MediaServer:1"
	scanInterval = time.Minute
	// A server not seen for this long is dropped, unless its advertised
	// max-age is longer.
	minLifetime = 3 * time.Minute
	// Descriptions are fetched again this often, to pick up renames.
	refetchAfter = 10 * time.Minute
	maxLearned   = 1024
)

// Server is a media server found on the LAN (or configured by hand).
type Server struct {
	UDN          string `json:"udn"`
	Name         string `json:"name"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Location     string `json:"location"`
	Icon         string `json:"icon,omitempty"`
	Manual       bool   `json:"manual,omitempty"`

	origins []string // host:port values this server is reached at
	expires time.Time
	fetched time.Time
}

// Registry is the current set of media servers.
type Registry struct {
	log     *slog.Logger
	client  *http.Client
	refresh chan struct{}

	mu      sync.Mutex
	manual  []string
	servers map[string]*Server // by location
	learned map[string]struct{}
}

// New returns a registry that also tracks the servers whose description
// URLs are listed in manual, for networks where multicast doesn't work.
func New(manual []string, log *slog.Logger) *Registry {
	return &Registry{
		log: log,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{Proxy: nil, DisableCompression: true},
		},
		manual:  manual,
		refresh: make(chan struct{}, 1),
		servers: map[string]*Server{},
		learned: map[string]struct{}{},
	}
}

// Run scans until ctx is done: every minute, and whenever Refresh is called.
func (r *Registry) Run(ctx context.Context) {
	t := time.NewTicker(scanInterval)
	defer t.Stop()
	for {
		r.scan(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.refresh:
		}
	}
}

// SetManual replaces the list of servers configured by hand, and rescans.
// Servers dropped from it go once their lifetime runs out.
func (r *Registry) SetManual(manual []string) {
	r.mu.Lock()
	r.manual = slices.Clone(manual)
	for _, s := range r.servers {
		if s.Manual && !slices.Contains(manual, s.Location) {
			s.Manual = false
			s.expires = time.Now()
		}
	}
	r.mu.Unlock()
	r.Refresh()
}

// Refresh asks for a scan now.
func (r *Registry) Refresh() {
	select {
	case r.refresh <- struct{}{}:
	default:
	}
}

// Servers returns the known servers, sorted by name.
func (r *Registry) Servers() []Server {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Server, 0, len(r.servers))
	for _, s := range r.servers {
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b Server) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.Location, b.Location))
	})
	return out
}

// Allowed reports whether hostport is a known server origin, or one learned
// from a server's responses.
func (r *Registry) Allowed(hostport string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.servers {
		if slices.Contains(s.origins, hostport) {
			return true
		}
	}
	_, ok := r.learned[hostport]
	return ok
}

// Learn records hostport, which appeared in a response from origin from, as
// relayable. Servers put URLs on other ports or hosts (album art, streams),
// and those must work through the launchpad too. Only LAN addresses are
// learned, and loopback only from a loopback server, so a server's response
// can't open the launchpad host's private services.
func (r *Registry) Learn(hostport, from string) bool {
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil || !lan.IsLAN(ap.Addr()) {
		return false
	}
	if ap.Addr().IsLoopback() {
		f, err := netip.ParseAddrPort(from)
		if err != nil || !f.Addr().IsLoopback() {
			return false
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.learned[hostport]; ok {
		return true
	}
	if len(r.learned) >= maxLearned {
		return false
	}
	r.learned[hostport] = struct{}{}
	return true
}

func (r *Registry) scan(ctx context.Context) {
	found := map[string]time.Duration{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ifc := range lan.IPv4() {
		wg.Go(func() {
			for loc, age := range search(ifc, r.log) {
				mu.Lock()
				found[loc] = max(found[loc], age)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	manual := map[string]bool{}
	r.mu.Lock()
	list := r.manual
	r.mu.Unlock()
	for _, m := range list {
		found[m] = max(found[m], 0)
		manual[m] = true
	}
	for loc, age := range found {
		wg.Go(func() { r.update(ctx, loc, age, manual[loc]) })
	}
	wg.Wait()
	r.expire()
}

func (r *Registry) update(ctx context.Context, loc string, maxAge time.Duration, manual bool) {
	now := time.Now()
	expires := now.Add(max(maxAge, minLifetime))
	r.mu.Lock()
	s := r.servers[loc]
	if s != nil && now.Sub(s.fetched) < refetchAfter {
		s.expires = expires
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()

	fresh, err := r.describe(ctx, loc)
	if err != nil {
		if s == nil {
			r.log.Debug("not a usable media server", "location", loc, "err", err)
		}
		return
	}
	fresh.Manual = manual
	fresh.expires = expires
	fresh.fetched = now
	r.mu.Lock()
	defer r.mu.Unlock()
	for other, o := range r.servers {
		if o.UDN == fresh.UDN && other != loc {
			delete(r.servers, other) // moved to a new address
		}
	}
	if s == nil {
		r.log.Info("media server found", "name", fresh.Name, "location", loc)
	}
	r.servers[loc] = fresh
}

func (r *Registry) expire() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for loc, s := range r.servers {
		if now.After(s.expires) {
			r.log.Info("media server gone", "name", s.Name, "location", loc)
			delete(r.servers, loc)
		}
	}
}

// search sends an SSDP M-SEARCH out of one interface and collects the
// description locations that answer within a few seconds.
func search(ifc lan.Interface, log *slog.Logger) map[string]time.Duration {
	c, err := net.ListenPacket("udp4", net.JoinHostPort(ifc.Addr.String(), "0"))
	if err != nil {
		log.Debug("ssdp: can't open socket", "interface", ifc.Name, "err", err)
		return nil
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)
	_ = p.SetMulticastInterface(&ifc.Interface)
	_ = p.SetMulticastTTL(2)

	msg := []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: " + searchTarget + "\r\n" +
		"USER-AGENT: minstrel-launchpad UPnP/1.1\r\n\r\n")
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for range 2 { // UDP may drop one
		if _, err := c.WriteTo(msg, dst); err != nil {
			log.Debug("ssdp: send failed", "interface", ifc.Name, "err", err)
			return nil
		}
	}

	out := map[string]time.Duration{}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8192)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return out
		}
		if loc, age, ok := parseResponse(buf[:n]); ok {
			out[loc] = max(out[loc], age)
		}
	}
}

func parseResponse(b []byte) (string, time.Duration, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", 0, false
	}
	loc := strings.TrimSpace(resp.Header.Get("Location"))
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "http" {
		return "", 0, false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !lan.IsLAN(ip) {
		return "", 0, false
	}
	return loc, maxAge(resp.Header.Get("Cache-Control")), true
}

func maxAge(cc string) time.Duration {
	for part := range strings.SplitSeq(cc, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "max-age") {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}

type descRoot struct {
	URLBase string     `xml:"URLBase"`
	Device  descDevice `xml:"device"`
}

type descDevice struct {
	DeviceType   string       `xml:"deviceType"`
	FriendlyName string       `xml:"friendlyName"`
	Manufacturer string       `xml:"manufacturer"`
	ModelName    string       `xml:"modelName"`
	UDN          string       `xml:"UDN"`
	Icons        []descIcon   `xml:"iconList>icon"`
	Devices      []descDevice `xml:"deviceList>device"`
}

type descIcon struct {
	Mimetype string `xml:"mimetype"`
	Width    int    `xml:"width"`
	URL      string `xml:"url"`
}

func (d *descDevice) mediaServer() *descDevice {
	if strings.Contains(d.DeviceType, ":device:MediaServer:") {
		return d
	}
	for i := range d.Devices {
		if s := d.Devices[i].mediaServer(); s != nil {
			return s
		}
	}
	return nil
}

func (r *Registry) describe(ctx context.Context, loc string) (*Server, error) {
	locURL, err := url.Parse(loc)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("description: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var root descRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	dev := root.Device.mediaServer()
	if dev == nil {
		return nil, errors.New("no MediaServer device in description")
	}

	base := locURL
	if b, err := url.Parse(strings.TrimSpace(root.URLBase)); err == nil && b.Scheme == "http" {
		base = b
	}
	s := &Server{
		UDN:          strings.TrimSpace(dev.UDN),
		Name:         strings.TrimSpace(dev.FriendlyName),
		Manufacturer: strings.TrimSpace(dev.Manufacturer),
		Model:        strings.TrimSpace(dev.ModelName),
		Location:     loc,
	}
	if s.Name == "" {
		s.Name = locURL.Host
	}
	s.origins = appendOrigin(nil, locURL)
	s.origins = appendOrigin(s.origins, base)
	if icon := bestIcon(dev.Icons); icon != "" {
		if u, err := base.Parse(icon); err == nil {
			s.Icon = u.String()
			s.origins = appendOrigin(s.origins, u)
		}
	}
	return s, nil
}

// HostPort returns u's host:port, with the scheme's default port filled in.
func HostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func appendOrigin(origins []string, u *url.URL) []string {
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !lan.IsLAN(ip) || u.Scheme != "http" {
		return origins
	}
	hp := HostPort(u)
	if slices.Contains(origins, hp) {
		return origins
	}
	return append(origins, hp)
}

// bestIcon prefers PNG, then the largest.
func bestIcon(icons []descIcon) string {
	best := -1
	score := func(i descIcon) int {
		s := i.Width
		if strings.Contains(i.Mimetype, "png") {
			s += 10000
		}
		return s
	}
	for i, ic := range icons {
		if strings.TrimSpace(ic.URL) == "" {
			continue
		}
		if best < 0 || score(ic) > score(icons[best]) {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	return strings.TrimSpace(icons[best].URL)
}
