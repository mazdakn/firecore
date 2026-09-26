package set

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/mazdakn/firecore/iputil"
)

// IPSet is a Set of netip.Prefix CIDR blocks. Networks are stored as netip.Prefix
// values in a slice, enabling high-performance, zero-allocation prefix matching on
// the packet-matching hot path via netip.Prefix.Contains.
type IPSet struct {
	prefixes []netip.Prefix
}

// NewIPSet returns an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{}
}

// indexOfPrefix returns the index of prefix in s.prefixes, or -1 if none matches.
func (s *IPSet) indexOfPrefix(prefix netip.Prefix) int {
	for i, existing := range s.prefixes {
		if existing == prefix {
			return i
		}
	}
	return -1
}

// toPrefix converts a supported value to a canonical netip.Prefix.
// Supported types: netip.Prefix, netip.Addr, *net.IPNet, net.IP, and string (CIDR or single IP).
func toPrefix(v any, op string) (netip.Prefix, error) {
	switch val := v.(type) {
	case netip.Prefix:
		if !val.IsValid() {
			return netip.Prefix{}, fmt.Errorf("IPSet.%s: invalid prefix", op)
		}
		return val.Masked(), nil
	case netip.Addr:
		if !val.IsValid() {
			return netip.Prefix{}, fmt.Errorf("IPSet.%s: invalid address", op)
		}
		addr := val.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	case *net.IPNet:
		if err := validateIPNet(val); err != nil {
			return netip.Prefix{}, err
		}
		addr, ok := netip.AddrFromSlice(val.IP)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("IPSet.%s: invalid IP in *net.IPNet: %v", op, val.IP)
		}
		addr = addr.Unmap()
		ones, _ := val.Mask.Size()
		return netip.PrefixFrom(addr, ones), nil
	case string:
		if prefix, err := netip.ParsePrefix(val); err == nil {
			return prefix.Masked(), nil
		}
		if addr, err := netip.ParseAddr(val); err == nil {
			addr = addr.Unmap()
			return netip.PrefixFrom(addr, addr.BitLen()), nil
		}
		// Fall back to iputil.ParseCIDROrIP to produce compatible error formatting
		parsed, err := iputil.ParseCIDROrIP(val)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q: %w", val, err)
		}
		addr, ok := netip.AddrFromSlice(parsed.IP)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q", val)
		}
		addr = addr.Unmap()
		ones, _ := parsed.Mask.Size()
		return netip.PrefixFrom(addr, ones), nil
	case net.IP:
		addr, ok := netip.AddrFromSlice(val)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("IPSet.%s: invalid net.IP: %v", op, val)
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	default:
		return netip.Prefix{}, fmt.Errorf("IPSet.%s: unsupported type %T", op, v)
	}
}

// Add inserts a value into the set. v must be a netip.Prefix, netip.Addr, *net.IPNet,
// net.IP, or a string representing an IP address (e.g. "10.0.0.1") or a CIDR block
// (e.g. "10.0.0.0/8"). It implements the Set interface.
func (s *IPSet) Add(v any) error {
	prefix, err := toPrefix(v, "Add")
	if err != nil {
		return err
	}

	if i := s.indexOfPrefix(prefix); i >= 0 {
		s.prefixes[i] = prefix
		return nil
	}
	s.prefixes = append(s.prefixes, prefix)
	return nil
}

// validateIPNet reports whether ipnet is well-formed: non-nil with a non-nil
// IP, a non-nil canonical Mask, and an IP length consistent with the mask.
func validateIPNet(ipnet *net.IPNet) error {
	if ipnet == nil {
		return fmt.Errorf("IPSet.Add: *net.IPNet must not be nil")
	}
	if ipnet.IP == nil {
		return fmt.Errorf("IPSet.Add: *net.IPNet has nil IP")
	}
	if ipnet.Mask == nil {
		return fmt.Errorf("IPSet.Add: *net.IPNet has nil Mask")
	}
	if _, bits := ipnet.Mask.Size(); bits == 0 {
		return fmt.Errorf("IPSet.Add: *net.IPNet has invalid mask %v", ipnet.Mask)
	}
	if len(ipnet.IP) != len(ipnet.Mask) {
		return fmt.Errorf("IPSet.Add: *net.IPNet IP length %d does not match mask length %d",
			len(ipnet.IP), len(ipnet.Mask))
	}
	return nil
}

// Delete removes a value from the set. v accepts the same types as Add: a
// netip.Prefix, netip.Addr, *net.IPNet, net.IP, or a string representing an
// IP address or CIDR block. It implements the Set interface.
func (s *IPSet) Delete(v any) error {
	prefix, err := toPrefix(v, "Delete")
	if err != nil {
		return err
	}

	if i := s.indexOfPrefix(prefix); i >= 0 {
		s.prefixes = append(s.prefixes[:i], s.prefixes[i+1:]...)
	}
	return nil
}

// Match reports whether v is contained in any network in the set.
// v must be a net.IP, netip.Addr, or string IP address. It implements the Set interface.
func (s *IPSet) Match(v any) bool {
	switch val := v.(type) {
	case net.IP:
		return s.MatchIP(val)
	case netip.Addr:
		return s.MatchAddr(val)
	case string:
		addr, err := netip.ParseAddr(val)
		if err != nil {
			return false
		}
		return s.MatchAddr(addr)
	default:
		return false
	}
}

// MatchAddr reports whether addr is contained in any prefix in the set.
func (s *IPSet) MatchAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// MatchIP reports whether ip is contained in any prefix in the set. Unlike
// Match, it takes a concrete net.IP rather than any, letting callers on the
// packet-matching hot path avoid interface-boxing it.
func (s *IPSet) MatchIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return s.MatchAddr(addr)
}

func (s *IPSet) Type() Type {
	return TypeIP
}

// Prefixes returns a copy of the netip.Prefix slices in the set.
func (s *IPSet) Prefixes() []netip.Prefix {
	copied := make([]netip.Prefix, len(s.prefixes))
	copy(copied, s.prefixes)
	return copied
}

// String returns a human-readable representation of the IPSet.
// A single-network set renders as its CIDR (e.g. "10.0.0.0/8").
// A multi-network set renders as a sorted brace-enclosed list (e.g. "{10.0.0.0/8,192.168.0.0/16}").
func (s *IPSet) String() string {
	cidrs := make([]string, 0, len(s.prefixes))
	for _, p := range s.prefixes {
		cidrs = append(cidrs, p.String())
	}
	sort.Strings(cidrs)
	if len(cidrs) == 1 {
		return cidrs[0]
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, cidr := range cidrs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(cidr)
	}
	sb.WriteByte('}')
	return sb.String()
}
