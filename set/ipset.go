package set

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/mazdakn/firecore/iputil"
)

// IPSet is a Set of IP addresses and CIDR blocks. Exact single-IP entries
// (/32 for IPv4, /128 for IPv6) are stored in the embedded set[netip.Addr]
// for O(1) lookup, while CIDR subnets are stored in nets.
type IPSet struct {
	set[netip.Addr]
	nets []netip.Prefix
}

// NewIPSet returns an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{
		set: *New[netip.Addr](),
	}
}

func toPrefix(op string, v any) (netip.Prefix, error) {
	switch val := v.(type) {
	case netip.Prefix:
		if !val.IsValid() {
			return netip.Prefix{}, fmt.Errorf("%s: netip.Prefix must be valid", op)
		}
		return val.Masked(), nil
	case netip.Addr:
		if !val.IsValid() {
			return netip.Prefix{}, fmt.Errorf("%s: netip.Addr must be valid", op)
		}
		return netip.PrefixFrom(val, val.BitLen()), nil
	case string:
		parsed, err := iputil.ParseCIDROrIP(val)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q: %w", val, err)
		}
		return parsed, nil
	default:
		return netip.Prefix{}, fmt.Errorf("%s: unsupported type %T", op, v)
	}
}

// Add inserts a value into the set. v must be either a netip.Prefix, a
// netip.Addr, or a string representing an IP address (e.g. "10.0.0.1") or a
// CIDR block (e.g. "10.0.0.0/8"). It implements the Set interface.
func (s *IPSet) Add(v any) error {
	prefix, err := toPrefix("IPSet.Add", v)
	if err != nil {
		return err
	}
	if prefix.IsSingleIP() {
		s.set.Add(prefix.Addr())
		return nil
	}
	if !slices.Contains(s.nets, prefix) {
		s.nets = append(s.nets, prefix)
	}
	return nil
}

// Delete removes a value from the set. v accepts the same types as Add: a
// netip.Prefix, a netip.Addr, or a string representing an IP address or CIDR
// block. It implements the Set interface.
func (s *IPSet) Delete(v any) error {
	prefix, err := toPrefix("IPSet.Delete", v)
	if err != nil {
		return err
	}
	if prefix.IsSingleIP() {
		s.set.Delete(prefix.Addr())
		return nil
	}
	if i := slices.Index(s.nets, prefix); i >= 0 {
		s.nets = slices.Delete(s.nets, i, i+1)
	}
	return nil
}

// Match reports whether v is contained in any network in the set.
// v must be a netip.Addr. It implements the Set interface.
func (s *IPSet) Match(v any) bool {
	ip, ok := v.(netip.Addr)
	if !ok {
		return false
	}
	return s.MatchIP(ip)
}

// MatchIP reports whether ip is contained in any network in the set. Unlike
// Match, it takes a concrete netip.Addr rather than any, letting callers on
// the packet-matching hot path avoid interface-boxing it.
func (s *IPSet) MatchIP(ip netip.Addr) bool {
	if s.Exists(ip) {
		return true
	}
	for _, prefix := range s.nets {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *IPSet) Type() Type {
	return TypeIP
}

// String returns a human-readable representation of the IPSet.
// A single-network set renders as its CIDR (e.g. "10.0.0.0/8").
// A multi-network set renders as a sorted brace-enclosed list (e.g. "{10.0.0.0/8,192.168.0.0/16}").
func (s *IPSet) String() string {
	cidrs := make([]string, 0, len(s.items)+len(s.nets))
	for ip := range s.items {
		cidrs = append(cidrs, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	for _, ipnet := range s.nets {
		cidrs = append(cidrs, ipnet.String())
	}
	return formatSortedStrings(cidrs)
}
