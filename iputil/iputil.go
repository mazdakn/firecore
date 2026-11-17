package iputil

import (
	"fmt"
	"net/netip"
)

// ParseCIDROrIP parses a string representing a CIDR block (e.g. "10.0.0.0/8")
// or a single IP address (e.g. "10.0.0.1"), returning a canonical netip.Prefix
// representing the network or host subnet (/32 for IPv4, /128 for IPv6).
func ParseCIDROrIP(v string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(v); err == nil {
		return prefix.Masked(), nil
	}
	if addr, err := netip.ParseAddr(v); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q", v)
}
