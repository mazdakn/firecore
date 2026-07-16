package matcher

import (
	"net"
	"slices"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/payload"
	"github.com/mazdakn/firecore/set"
)

// Matcher evaluates a single match condition against a packet and the
// connection-tracking state it was classified as. A Rule matches only when
// every one of its Matchers matches.
type Matcher interface {
	Match(pkt *packet.Packet, state conntrack.State) (bool, error)
}

// Negated wraps a Matcher and inverts its result. It is the single negation
// mechanism for every matcher type, replacing what would otherwise be a
// duplicate "Not*" type per condition.
type Negated struct {
	Matcher
}

// Negate wraps m so that its Match result is inverted.
func Negate(m Matcher) Matcher {
	return Negated{m}
}

func (n Negated) Match(pkt *packet.Packet, state conntrack.State) (bool, error) {
	ok, err := n.Matcher.Match(pkt, state)
	if err != nil {
		return false, err
	}
	return !ok, nil
}

// matchNamedSet reports whether s matches the value corresponding to its
// type: an IP set is matched against ip, a port set against port, an
// IP:port set against the (ip, port) tuple, and an interface set against
// iface.
//
// It dispatches on s's concrete type rather than going through Set.Match(any)
// as Type() dispatch would: calling Match(any) via the Set interface forces
// the compiler to heap-allocate the boxed argument (ip/port/iface), since
// escape analysis can't see into an unknown interface method. A type switch
// on the concrete pointer lets it call the typed Match* method directly,
// keeping the argument on the stack.
func matchNamedSet(s set.Set, ip net.IP, port uint16, iface string) bool {
	switch cs := s.(type) {
	case *set.IPSet:
		return cs.MatchIP(ip)
	case *set.PortSet:
		return cs.MatchPort(port)
	case *set.IPPortSet:
		return cs.MatchIPPort(set.IPPortTuple{IP: ip, Port: port})
	case *set.IfaceSet:
		return cs.MatchIface(iface)
	default:
		return false
	}
}

// ProtoMatcher matches packets whose protocol is in Protos.
type ProtoMatcher struct {
	Protos *set.ProtoSet
}

func (m *ProtoMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Protos.Match(pkt.Proto), nil
}

// SrcSetMatcher matches packets whose source-derived value (address, port,
// or interface, depending on Set's type) is in Set.
type SrcSetMatcher struct {
	Set set.Set
}

func (m *SrcSetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return matchNamedSet(m.Set, pkt.SrcAddr, pkt.SrcPort, pkt.Metadata.IngressIface), nil
}

// DstSetMatcher matches packets whose destination-derived value (address,
// port, or interface, depending on Set's type) is in Set.
type DstSetMatcher struct {
	Set set.Set
}

func (m *DstSetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return matchNamedSet(m.Set, pkt.DstAddr, pkt.DstPort, pkt.Metadata.EgressIface), nil
}

// ConnStateMatcher matches packets whose connection-tracking state is in States.
type ConnStateMatcher struct {
	States []conntrack.State
}

func (m *ConnStateMatcher) Match(_ *packet.Packet, state conntrack.State) (bool, error) {
	return slices.Contains(m.States, state), nil
}

// PayloadMatcher matches packets whose payload matches Payload's pattern.
type PayloadMatcher struct {
	Payload *payload.Matcher
}

func (m *PayloadMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Payload.Match(pkt.Payload), nil
}
