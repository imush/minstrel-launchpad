package auth

import (
	"net/netip"
	"sync"
	"time"
)

// Limiter blocks clients after repeated failed authentication. IPv6 clients
// are counted per /64, since one host can use a whole /64.
type Limiter struct {
	MaxFailures int
	Window      time.Duration
	Block       time.Duration

	mu      sync.Mutex
	clients map[string]*client
}

type client struct {
	fails        int
	since        time.Time
	blockedUntil time.Time
}

// NewLimiter allows 10 failures per 10 minutes, then blocks for 15 minutes.
func NewLimiter() *Limiter {
	return &Limiter{MaxFailures: 10, Window: 10 * time.Minute, Block: 15 * time.Minute, clients: map[string]*client{}}
}

// Key identifies the client at remoteAddr (an http.Request.RemoteAddr).
func Key(remoteAddr string) string {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	a := ap.Addr().Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// Blocked reports whether key is currently blocked.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.clients[key]
	return c != nil && time.Now().Before(c.blockedUntil)
}

// Fail records a failed attempt by key.
func (l *Limiter) Fail(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.clients) > 10000 {
		for k, c := range l.clients {
			if now.Sub(c.since) > l.Window && now.After(c.blockedUntil) {
				delete(l.clients, k)
			}
		}
	}
	c := l.clients[key]
	if c == nil || now.Sub(c.since) > l.Window {
		c = &client{since: now, blockedUntil: c.blockedUntilOrZero()}
		l.clients[key] = c
	}
	c.fails++
	if c.fails >= l.MaxFailures {
		c.blockedUntil = now.Add(l.Block)
		c.fails = 0
		c.since = now
	}
}

func (c *client) blockedUntilOrZero() time.Time {
	if c == nil {
		return time.Time{}
	}
	return c.blockedUntil
}
