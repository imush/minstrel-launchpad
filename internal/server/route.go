package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/imush/minstrel-launchpad/internal/auth"
)

// How a request reached the launchpad. Direct and satellite traffic share
// one http.Server, so the satellite's connections are marked as they are
// accepted and read back here.

type satelliteKey struct{}

// SatelliteConn marks a connection accepted from a satellite's listener.
type SatelliteConn struct{ net.Conn }

// SatelliteListener marks everything it accepts.
type SatelliteListener struct{ net.Listener }

func (l SatelliteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return SatelliteConn{Conn: c}, nil
}

// ConnContext notes satellite connections. Give it to http.Server. TLS
// wraps the listener, so the marked connection is one layer down.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if _, ok := c.(SatelliteConn); ok {
		return context.WithValue(ctx, satelliteKey{}, true)
	}
	return ctx
}

// RouteOf says how a request arrived: through a satellite, straight to the
// launchpad from outside, or from the home network.
func RouteOf(r *http.Request) auth.Route {
	if viaSatellite, _ := r.Context().Value(satelliteKey{}).(bool); viaSatellite {
		return auth.RouteSatellite
	}
	if addr, err := netip.ParseAddr(remoteIP(r)); err == nil &&
		(addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()) {
		return auth.RouteHome
	}
	return auth.RouteDirect
}

// videoRefused turns an upstream answer into a refusal, before its body is
// read. The message is shown to whoever asked, so it says what to change
// and where, not merely that something was denied.
func videoRefused(resp *http.Response, route auth.Route) error {
	why := "Video from outside your home network is turned off for this device."
	if route == auth.RouteSatellite {
		why = "Video through the satellite relay is turned off for this device."
	}
	body := why + " The launchpad's owner can change it on the console, under the device's video setting.\n"
	_ = resp.Body.Close()
	resp.StatusCode = http.StatusForbidden
	resp.Status = "403 Forbidden"
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header = http.Header{}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("X-Launchpad-Error", "video-not-allowed")
	return nil
}
