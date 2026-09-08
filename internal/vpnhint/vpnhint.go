// Package vpnhint reports whether this machine looks like it has a VPN tunnel
// up, by looking at network interface names.
//
// This is a HINT, never a verdict. A modified agent could lie about it, so the
// control plane treats it as one weak signal and relies instead on the source
// address of the agent's own connection, which the agent cannot forge.
//
// Listing interfaces needs no elevated privileges on any supported platform.
package vpnhint

import (
	"net"
	"strings"
)

var tunnelPrefixes = []string{"tun", "tap", "utun", "wg", "ppp", "ipsec", "gpd", "nordlynx"}

var tunnelSubstrings = []string{
	"wireguard", "openvpn", "tap-windows", "nordvpn", "protonvpn",
	"expressvpn", "tailscale", "zerotier", "mullvad",
}

// LikelyBehindTunnel reports whether any active, non-loopback interface looks
// like a VPN/tunnel adapter.
//
// Note for reviewers: macOS always creates utun* interfaces for its own
// features, so this returns true on most Macs regardless of VPN use. That is
// exactly why it is only a hint.
func LikelyBehindTunnel() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		for _, prefix := range tunnelPrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		for _, needle := range tunnelSubstrings {
			if strings.Contains(name, needle) {
				return true
			}
		}
	}
	return false
}
