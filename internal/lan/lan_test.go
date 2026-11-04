package lan

import "testing"

func TestVirtual(t *testing.T) {
	// Host-side interfaces of container and VM runtimes: private addresses
	// that no phone can reach.
	for _, n := range []string{"docker0", "br-1a2b3c4d5e6f", "veth7f3a1c2", "virbr0", "vmnet8", "podman0"} {
		if !virtual(n) {
			t.Errorf("%s should be treated as virtual", n)
		}
	}
	// Real home-network interfaces, including what a container or jail sees
	// from the inside, and FreeBSD's bridge, which is a genuine LAN bridge.
	for _, n := range []string{"eth0", "en0", "epair0b", "bridge0", "wlan0", "enp3s0", "igb0"} {
		if virtual(n) {
			t.Errorf("%s should not be treated as virtual", n)
		}
	}
}
