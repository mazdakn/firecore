package set

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/mazdakn/firecore/iputil"
	"github.com/mazdakn/firecore/port"
)

type ipPortMember struct {
	net   netip.Prefix
	start uint16
	end   uint16
}

func (m ipPortMember) isExact() bool {
	return m.net.IsSingleIP() && m.start == m.end
}

func (m ipPortMember) addrPort() netip.AddrPort {
	return netip.AddrPortFrom(m.net.Addr(), m.start)
}

func (m ipPortMember) String() string {
	portExpr := strconv.Itoa(int(m.start))
	if m.end > m.start {
		portExpr = fmt.Sprintf("%d-%d", m.start, m.end)
	}
	return fmt.Sprintf("%s,%s", m.net.String(), portExpr)
}

// IPPortSet matches an IP and port pair. Exact (single-IP, single-port)
// entries are stored in the embedded set[netip.AddrPort] for O(1) lookup,
// while CIDR or port-range entries are stored in members.
type IPPortSet struct {
	set[netip.AddrPort]
	members []ipPortMember
}

// NewIPPortSet returns an empty IPPortSet.
func NewIPPortSet() *IPPortSet {
	return &IPPortSet{
		set:     *New[netip.AddrPort](),
		members: nil,
	}
}

// Add inserts a value into the set.
// v must be a netip.AddrPort or a string in the form "ip-or-cidr,port-or-range"
// or "ip:port" / "[ipv6]:port".
func (s *IPPortSet) Add(v any) error {
	member, err := toIPPortMember("IPPortSet.Add", v)
	if err != nil {
		return err
	}
	if member.isExact() {
		s.set.Add(member.addrPort())
		return nil
	}
	if !slices.Contains(s.members, member) {
		s.members = append(s.members, member)
	}
	return nil
}

// Delete removes a value from the set. v accepts the same types as Add: a
// netip.AddrPort or a string in the "ip-or-cidr,port-or-range" or "ip:port" form.
func (s *IPPortSet) Delete(v any) error {
	member, err := toIPPortMember("IPPortSet.Delete", v)
	if err != nil {
		return err
	}
	if member.isExact() {
		s.set.Delete(member.addrPort())
		return nil
	}
	if i := slices.Index(s.members, member); i >= 0 {
		s.members = slices.Delete(s.members, i, i+1)
	}
	return nil
}

func toIPPortMember(op string, v any) (ipPortMember, error) {
	switch val := v.(type) {
	case netip.AddrPort:
		if !val.IsValid() {
			return ipPortMember{}, fmt.Errorf("%s: netip.AddrPort must be valid", op)
		}
		addr := val.Addr()
		p := val.Port()
		return ipPortMember{
			net:   netip.PrefixFrom(addr, addr.BitLen()),
			start: p,
			end:   p,
		}, nil
	case string:
		return parseIPPortMember(val)
	default:
		return ipPortMember{}, fmt.Errorf("%s: unsupported type %T", op, v)
	}
}

// Match reports whether v is contained in the set.
// v must be a netip.AddrPort value.
func (s *IPPortSet) Match(v any) bool {
	ap, ok := v.(netip.AddrPort)
	if !ok {
		return false
	}
	return s.MatchIPPort(ap)
}

// MatchIPPort reports whether ap is contained in the set. Unlike Match, it
// takes a concrete netip.AddrPort rather than any, letting callers on the
// packet-matching hot path avoid interface-boxing it.
func (s *IPPortSet) MatchIPPort(ap netip.AddrPort) bool {
	if s.Exists(ap) {
		return true
	}
	ip := ap.Addr()
	p := ap.Port()
	for _, member := range s.members {
		if !member.net.Contains(ip) {
			continue
		}
		if p < member.start || p > member.end {
			continue
		}
		return true
	}
	return false
}

func (s *IPPortSet) Type() Type {
	return TypeIPPort
}

// String returns a human-readable representation of the IPPortSet.
func (s *IPPortSet) String() string {
	memberStrings := make([]string, 0, len(s.items)+len(s.members))
	for ap := range s.items {
		addr := ap.Addr()
		m := ipPortMember{
			net:   netip.PrefixFrom(addr, addr.BitLen()),
			start: ap.Port(),
			end:   ap.Port(),
		}
		memberStrings = append(memberStrings, m.String())
	}
	for _, member := range s.members {
		memberStrings = append(memberStrings, member.String())
	}
	return formatSortedStrings(memberStrings)
}

func parseIPPortMember(v string) (ipPortMember, error) {
	if !strings.Contains(v, ",") {
		if ap, err := netip.ParseAddrPort(v); err == nil {
			addr := ap.Addr()
			p := ap.Port()
			return ipPortMember{
				net:   netip.PrefixFrom(addr, addr.BitLen()),
				start: p,
				end:   p,
			}, nil
		}
	}
	parts := strings.Split(v, ",")
	if len(parts) != 2 {
		return ipPortMember{}, fmt.Errorf("invalid ipport member %q: expected format ip-or-cidr,port", v)
	}
	ipExpr := strings.TrimSpace(parts[0])
	portExpr := strings.TrimSpace(parts[1])

	ipnet, err := iputil.ParseCIDROrIP(ipExpr)
	if err != nil {
		return ipPortMember{}, fmt.Errorf("invalid ip in %q: %w", v, err)
	}
	parsedPort, err := port.Parse(portExpr)
	if err != nil {
		return ipPortMember{}, fmt.Errorf("invalid port in %q: %w", v, err)
	}
	start := parsedPort.Number
	end := parsedPort.Number
	if parsedPort.IsRange() {
		end = parsedPort.End
	}
	return ipPortMember{
		net:   ipnet,
		start: start,
		end:   end,
	}, nil
}
