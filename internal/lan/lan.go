// Package lan identifies home-network addresses and interfaces.
package lan

import (
	"net"
	"net/netip"
)

// IsLAN reports whether a is a private, link-local or loopback address:
// one that can only be a device at home, never somewhere on the internet.
func IsLAN(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback()
}

// Interface is a network interface with one of its IPv4 addresses.
type Interface struct {
	net.Interface
	Addr netip.Addr
}

// IPv4 lists the interfaces that face the home network: up, multicast
// capable, not loopback, with a private IPv4 address. A router's WAN side
// has a public (or carrier NAT) address and is left out, so discovery never
// reaches beyond the home.
func IPv4() []Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Interface
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			if ip := p.Addr(); ip.Is4() && IsLAN(ip) {
				out = append(out, Interface{ifc, ip})
			}
		}
	}
	return out
}
