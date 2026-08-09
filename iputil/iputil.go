package iputil

import (
	"fmt"
	"net"
)

// ParseCIDROrIP parses a string representing a CIDR block (e.g. "10.0.0.0/8")
// or a single IP address (e.g. "10.0.0.1"), returning a *net.IPNet representing
// the network or host subnet (/32 for IPv4, /128 for IPv6).
func ParseCIDROrIP(v string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(v); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP/CIDR %q", v)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
