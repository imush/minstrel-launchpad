// Package rewrite translates URLs between the home network and the
// launchpad's public address.
//
// Servers put LAN URLs everywhere: device descriptions, DIDL-Lite resources
// and album art, icon lists, playlists, redirect headers. Rather than
// knowing every place, the launchpad makes one general pass over every
// text body and header value, replacing http://<LAN IP>[:port] with
// <base>/u/<IP>:<port>.
package rewrite

import (
	"bytes"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/imush/minstrel-launchpad/internal/lan"
)

// Keep decides whether a LAN origin (host:port) should be reached through
// the launchpad, recording it as relayable if so.
type Keep func(hostport string) bool

var (
	lanURL = regexp.MustCompile(`http://(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?`)
	ourURL = regexp.MustCompile(`https?://[^/\s"'<>&]+(?:/[A-Za-z0-9._~-]+)*/u/(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})`)

	// Absolute-path URLs in a device description, which would otherwise
	// resolve against the launchpad's root instead of the server.
	pathTag = regexp.MustCompile(`(<(?:\w+:)?(?:controlURL|eventSubURL|SCPDURL|url|presentationURL)>\s*)/([^/<])`)
	urlBase = regexp.MustCompile(`<(?:\w+:)?URLBase>\s*(http://[^<\s]+)`)
)

// ToClient rewrites LAN URLs in b to go through the launchpad at base,
// such as "https://home.example.net:8443". Public addresses are left alone.
func ToClient(b []byte, base string, keep Keep) []byte {
	matches := lanURL.FindAllSubmatchIndex(b, -1)
	if matches == nil {
		return b
	}
	var out bytes.Buffer
	out.Grow(len(b) + len(matches)*(len(base)+8))
	last := 0
	for _, m := range matches {
		ip, err := netip.ParseAddr(string(b[m[2]:m[3]]))
		if err != nil || !lan.IsLAN(ip) {
			continue
		}
		port := 80
		if m[4] >= 0 {
			port, _ = strconv.Atoi(string(b[m[4]:m[5]]))
		}
		if port < 1 || port > 65535 {
			continue
		}
		hp := ip.String() + ":" + strconv.Itoa(port)
		if !keep(hp) {
			continue
		}
		out.Write(b[last:m[0]])
		out.WriteString(base)
		out.WriteString("/u/")
		out.WriteString(hp)
		last = m[1]
	}
	if last == 0 {
		return b
	}
	out.Write(b[last:])
	return out.Bytes()
}

// ToLAN turns launchpad URLs in b back into the LAN URLs they stand for,
// for bodies sent to servers (and, later, renderers).
func ToLAN(b []byte) []byte {
	if !bytes.Contains(b, []byte("/u/")) {
		return b
	}
	return ourURL.ReplaceAll(b, []byte("http://$1"))
}

// Body rewrites a response body that came from origin (host:port).
func Body(b []byte, base, origin string, keep Keep) []byte {
	if bytes.Contains(b, []byte("urn:schemas-upnp-org:device-1-0")) {
		o := origin
		if m := urlBase.FindSubmatch(b); m != nil {
			if u, err := url.Parse(string(m[1])); err == nil && u.Hostname() != "" {
				port := u.Port()
				if port == "" {
					port = "80"
				}
				o = u.Hostname() + ":" + port
			}
		}
		prefix := ""
		if u, err := url.Parse(base); err == nil {
			prefix = strings.TrimSuffix(u.EscapedPath(), "/")
		}
		b = pathTag.ReplaceAll(b, []byte("${1}"+prefix+"/u/"+o+"/${2}"))
	}
	return ToClient(b, base, keep)
}

// Headers applies f to every header value.
func Headers(h http.Header, f func([]byte) []byte) {
	for _, vs := range h {
		for i, v := range vs {
			vs[i] = string(f([]byte(v)))
		}
	}
}

// Rewritable reports whether a body of this content type may hold URLs:
// XML, JSON, text and playlists. Audio and images pass through untouched.
func Rewritable(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mt, "text/") ||
		strings.HasSuffix(mt, "xml") ||
		strings.HasSuffix(mt, "json") ||
		strings.Contains(mt, "mpegurl") ||
		strings.Contains(mt, "scpls")
}
