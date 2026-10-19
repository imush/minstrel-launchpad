// Package satellite keeps the launchpad reachable through a
// minstrel-satellite, for homes the app can't reach directly. The launchpad
// dials out, so nothing needs forwarding on the router.
package satellite

import (
	"crypto/tls"
	"log/slog"
	"net"
	"sync"

	"github.com/imush/minstrel-satellite/tunnel"
)

// Manager runs the link to the satellite set on the console, if any.
type Manager struct {
	// Cert is the launchpad's certificate; the satellite names the home
	// after its key.
	Cert tls.Certificate
	// Name is what the satellite lists the home as.
	Name func() string
	Log  *slog.Logger
	// Serve serves the launchpad's API on the phones the satellite hands
	// over; it returns when the listener is closed.
	Serve func(net.Listener)
	// Saved is called with the link to keep once the satellite has used up
	// the invitation code in it.
	Saved func(link string)

	mu   sync.Mutex
	l    *tunnel.Listener
	link tunnel.Link
}

// Status is what the console shows.
type Status struct {
	tunnel.Status
	// Satellite is the satellite's host:port; empty when none is set.
	Satellite string `json:"satellite,omitempty"`
	// Pending is true until the satellite has taken the invitation code.
	Pending bool `json:"pending,omitempty"`
}

// Set switches to the satellite in link, or to none for "". The old link,
// if any, is closed; phones already connected through it stay.
func (m *Manager) Set(link string) error {
	var parsed tunnel.Link
	if link != "" {
		var err error
		if parsed, err = tunnel.ParseLink(link); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.l != nil {
		m.l.Close()
		m.l = nil
	}
	m.link = parsed
	if link == "" {
		return nil
	}
	name := ""
	if m.Name != nil {
		name = m.Name()
	}
	var l *tunnel.Listener
	l = tunnel.Listen(tunnel.Config{
		Link: parsed, Cert: m.Cert, Name: name, Log: m.Log,
		OnEnrolled: func() { m.enrolled(l) },
	})
	m.l = l
	go m.Serve(l)
	return nil
}

func (m *Manager) enrolled(l *tunnel.Listener) {
	m.mu.Lock()
	if m.l != l {
		m.mu.Unlock()
		return
	}
	m.link.Code = ""
	link := m.link.String()
	m.mu.Unlock()
	m.Log.Info("enrolled at the satellite", "satellite", m.link.Addr)
	if m.Saved != nil {
		m.Saved(link)
	}
}

// Status reports the link's state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.l == nil {
		return Status{}
	}
	return Status{Status: m.l.Status(), Satellite: m.link.Addr, Pending: m.link.Code != ""}
}

// Hosts is where phones reach this home through the satellite: none until
// the home is enrolled there.
func (m *Manager) Hosts() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.l == nil || m.link.Code != "" {
		return nil
	}
	if h := m.l.Status().Host; h != "" {
		return []string{h}
	}
	// Not connected right now: the name doesn't change, so still list it.
	_, port, _ := net.SplitHostPort(m.link.Addr)
	id := tunnel.HomeID(m.Cert.Leaf.RawSubjectPublicKeyInfo)
	return []string{net.JoinHostPort(id+"."+m.link.Domain(), port)}
}

// Close drops the link.
func (m *Manager) Close() { _ = m.Set("") }
