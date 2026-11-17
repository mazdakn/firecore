package set

import (
	"fmt"
	"net/netip"

	"github.com/mazdakn/firecore/iputil"
)

// IPSet is a Set of netip.Prefix CIDR blocks. Networks are stored in a slice
// rather than keyed by CIDR string, since MatchIP runs on the packet-matching
// hot path and a slice scan avoids Go map iteration's per-element bucket-walk
// overhead; Add is a config-time operation, so the linear dedup scan it does
// instead is not a concern.
type IPSet struct {
	nets []netip.Prefix
}

// NewIPSet returns an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{}
}

// indexOfNet returns the index of the network in s.nets that equals prefix,
// or -1 if none does.
func (s *IPSet) indexOfNet(prefix netip.Prefix) int {
	for i, existing := range s.nets {
		if existing == prefix {
			return i
		}
	}
	return -1
}

// Add inserts a value into the set. v must be either a netip.Prefix, a
// netip.Addr, or a string representing an IP address (e.g. "10.0.0.1") or a
// CIDR block (e.g. "10.0.0.0/8"). It implements the Set interface.
func (s *IPSet) Add(v any) error {
	var prefix netip.Prefix
	switch val := v.(type) {
	case netip.Prefix:
		if !val.IsValid() {
			return fmt.Errorf("IPSet.Add: netip.Prefix must be valid")
		}
		prefix = val.Masked()
	case netip.Addr:
		if !val.IsValid() {
			return fmt.Errorf("IPSet.Add: netip.Addr must be valid")
		}
		prefix = netip.PrefixFrom(val, val.BitLen())
	case string:
		parsed, err := iputil.ParseCIDROrIP(val)
		if err != nil {
			return fmt.Errorf("invalid IP/CIDR %q: %w", val, err)
		}
		prefix = parsed
	default:
		return fmt.Errorf("IPSet.Add: unsupported type %T", v)
	}

	if i := s.indexOfNet(prefix); i >= 0 {
		s.nets[i] = prefix
		return nil
	}
	s.nets = append(s.nets, prefix)
	return nil
}

// Delete removes a value from the set. v accepts the same types as Add: a
// netip.Prefix, a netip.Addr, or a string representing an IP address or CIDR
// block. It implements the Set interface.
func (s *IPSet) Delete(v any) error {
	var prefix netip.Prefix
	switch val := v.(type) {
	case netip.Prefix:
		if !val.IsValid() {
			return fmt.Errorf("IPSet.Delete: netip.Prefix must be valid")
		}
		prefix = val.Masked()
	case netip.Addr:
		if !val.IsValid() {
			return fmt.Errorf("IPSet.Delete: netip.Addr must be valid")
		}
		prefix = netip.PrefixFrom(val, val.BitLen())
	case string:
		parsed, err := iputil.ParseCIDROrIP(val)
		if err != nil {
			return fmt.Errorf("invalid IP/CIDR %q: %w", val, err)
		}
		prefix = parsed
	default:
		return fmt.Errorf("IPSet.Delete: unsupported type %T", v)
	}

	if i := s.indexOfNet(prefix); i >= 0 {
		s.nets = append(s.nets[:i], s.nets[i+1:]...)
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
	cidrs := make([]string, 0, len(s.nets))
	for _, ipnet := range s.nets {
		cidrs = append(cidrs, ipnet.String())
	}
	return formatSortedStrings(cidrs)
}
