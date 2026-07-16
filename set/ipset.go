package set

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// IPSet is a Set of net.IPNet CIDR blocks.
type IPSet struct {
	nets map[string]*net.IPNet
}

// NewIPSet returns an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{
		nets: make(map[string]*net.IPNet),
	}
}

// Add inserts a value into the set. v must be either a *net.IPNet or a string
// in CIDR notation. It implements the Set interface.
func (s *IPSet) Add(v any) error {
	switch val := v.(type) {
	case *net.IPNet:
		if err := validateIPNet(val); err != nil {
			return err
		}
		s.nets[val.String()] = val
		return nil
	case string:
		_, ipnet, err := net.ParseCIDR(val)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", val, err)
		}
		s.nets[ipnet.String()] = ipnet
		return nil
	default:
		return fmt.Errorf("IPSet.Add: unsupported type %T", v)
	}
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

// Delete removes ipnet from the set.
func (s *IPSet) Delete(ipnet *net.IPNet) {
	delete(s.nets, ipnet.String())
}

// Match reports whether v is contained in any network in the set.
// v must be a net.IP. It implements the Set interface.
func (s *IPSet) Match(v any) bool {
	ip, ok := v.(net.IP)
	if !ok {
		return false
	}
	return s.MatchIP(ip)
}

// MatchIP reports whether ip is contained in any network in the set. Unlike
// Match, it takes a concrete net.IP rather than any, letting callers on the
// packet-matching hot path avoid interface-boxing it.
func (s *IPSet) MatchIP(ip net.IP) bool {
	for _, ipnet := range s.nets {
		if ipnet.Contains(ip) {
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
	for cidr := range s.nets {
		cidrs = append(cidrs, cidr)
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
