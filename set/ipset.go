package set

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// IPSet is a Set of net.IPNet CIDR blocks. Networks are stored in a slice
// rather than keyed by CIDR string, since MatchIP runs on the packet-matching
// hot path and a slice scan avoids Go map iteration's per-element bucket-walk
// overhead; Add/Delete are config-time operations, so the linear dedup scan
// they do instead is not a concern.
type IPSet struct {
	nets []*net.IPNet
}

// NewIPSet returns an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{}
}

// indexOfNet returns the index of the network in s.nets whose CIDR string
// matches ipnet's, or -1 if none does.
func (s *IPSet) indexOfNet(ipnet *net.IPNet) int {
	cidr := ipnet.String()
	for i, existing := range s.nets {
		if existing.String() == cidr {
			return i
		}
	}
	return -1
}

// Add inserts a value into the set. v must be either a *net.IPNet or a string
// in CIDR notation. It implements the Set interface.
func (s *IPSet) Add(v any) error {
	var ipnet *net.IPNet
	switch val := v.(type) {
	case *net.IPNet:
		if err := validateIPNet(val); err != nil {
			return err
		}
		ipnet = val
	case string:
		_, parsed, err := net.ParseCIDR(val)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", val, err)
		}
		ipnet = parsed
	default:
		return fmt.Errorf("IPSet.Add: unsupported type %T", v)
	}

	if i := s.indexOfNet(ipnet); i >= 0 {
		s.nets[i] = ipnet
		return nil
	}
	s.nets = append(s.nets, ipnet)
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

// Delete removes ipnet from the set.
func (s *IPSet) Delete(ipnet *net.IPNet) {
	if i := s.indexOfNet(ipnet); i >= 0 {
		s.nets = append(s.nets[:i], s.nets[i+1:]...)
	}
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
	for _, ipnet := range s.nets {
		cidrs = append(cidrs, ipnet.String())
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
