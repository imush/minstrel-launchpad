// Package lan identifies home-network addresses and interfaces.
package lan

import (
	"net"
	"net/netip"
	"strings"
)

// IsLAN reports whether a is a private, link-local or loopback address:
// one that can only be a device at home, never somewhere on the internet.
func IsLAN(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback()
}

// Virtual interfaces that container and VM runtimes add to a host. They
// carry private addresses, so they look like the home network, but nothing
// can reach the launchpad there: a phone handed docker0's 172.17.0.1 only
// waits for it to time out. Names seen from *inside* a container or jail --
// eth0, epair0b -- are deliberately absent: in there, that interface is the
// home network.
var virtualIfaces = []string{
	"docker", "br-", "veth", "virbr", "vmnet", "lxcbr", "lxdbr", "podman",
	"cni", "flannel",
}

func virtual(name string) bool {
	for _, p := range virtualIfaces {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Interface is a network interface with one of its IPv4 addresses.
type Interface struct {
	net.Interface
	Addr netip.Addr
}

// IPv4 lists the interfaces that face the home network: up, multicast
// capable, not loopback or virtual, with a private IPv4 address. A router's
// WAN side has a public (or carrier NAT) address and is left out, so
// discovery never reaches beyond the home.
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
		if virtual(ifc.Name) {
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
