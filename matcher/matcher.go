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

// matchNamedSet reports whether s matches the value corresponding to its
// type: an IP set is matched against ip, a port set against port, an
// IP:port set against the (ip, port) tuple, and an interface set against
// iface.
func matchNamedSet(s set.Set, ip net.IP, port uint16, iface string) bool {
	switch s.Type() {
	case set.TypeIP:
		return s.Match(ip)
	case set.TypePort:
		return s.Match(port)
	case set.TypeIPPort:
		return s.Match(set.IPPortTuple{IP: ip, Port: port})
	case set.TypeIface:
		return s.Match(iface)
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

// NotProtoMatcher matches packets whose protocol is not in Protos.
type NotProtoMatcher struct {
	Protos *set.ProtoSet
}

func (m *NotProtoMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Protos.Match(pkt.Proto), nil
}

// SrcPortMatcher matches packets whose source port is in Ports.
type SrcPortMatcher struct {
	Ports *set.PortSet
}

func (m *SrcPortMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Ports.Match(pkt.SrcPort), nil
}

// NotSrcPortMatcher matches packets whose source port is not in Ports.
type NotSrcPortMatcher struct {
	Ports *set.PortSet
}

func (m *NotSrcPortMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Ports.Match(pkt.SrcPort), nil
}

// DstPortMatcher matches packets whose destination port is in Ports.
type DstPortMatcher struct {
	Ports *set.PortSet
}

func (m *DstPortMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Ports.Match(pkt.DstPort), nil
}

// NotDstPortMatcher matches packets whose destination port is not in Ports.
type NotDstPortMatcher struct {
	Ports *set.PortSet
}

func (m *NotDstPortMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Ports.Match(pkt.DstPort), nil
}

// SrcNetMatcher matches packets whose source address is in Nets.
type SrcNetMatcher struct {
	Nets *set.IPSet
}

func (m *SrcNetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Nets.Match(pkt.SrcAddr), nil
}

// NotSrcNetMatcher matches packets whose source address is not in Nets.
type NotSrcNetMatcher struct {
	Nets *set.IPSet
}

func (m *NotSrcNetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Nets.Match(pkt.SrcAddr), nil
}

// DstNetMatcher matches packets whose destination address is in Nets.
type DstNetMatcher struct {
	Nets *set.IPSet
}

func (m *DstNetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Nets.Match(pkt.DstAddr), nil
}

// NotDstNetMatcher matches packets whose destination address is not in Nets.
type NotDstNetMatcher struct {
	Nets *set.IPSet
}

func (m *NotDstNetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Nets.Match(pkt.DstAddr), nil
}

// SrcIfaceMatcher matches packets whose ingress interface is in Ifaces.
type SrcIfaceMatcher struct {
	Ifaces *set.IfaceSet
}

func (m *SrcIfaceMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Ifaces.Match(pkt.Metadata.IngressIface), nil
}

// NotSrcIfaceMatcher matches packets whose ingress interface is not in Ifaces.
type NotSrcIfaceMatcher struct {
	Ifaces *set.IfaceSet
}

func (m *NotSrcIfaceMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Ifaces.Match(pkt.Metadata.IngressIface), nil
}

// DstIfaceMatcher matches packets whose egress interface is in Ifaces.
type DstIfaceMatcher struct {
	Ifaces *set.IfaceSet
}

func (m *DstIfaceMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Ifaces.Match(pkt.Metadata.EgressIface), nil
}

// NotDstIfaceMatcher matches packets whose egress interface is not in Ifaces.
type NotDstIfaceMatcher struct {
	Ifaces *set.IfaceSet
}

func (m *NotDstIfaceMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Ifaces.Match(pkt.Metadata.EgressIface), nil
}

// SrcSetMatcher matches packets whose source-derived value (address, port,
// or interface, depending on Set's type) is in Set.
type SrcSetMatcher struct {
	Set set.Set
}

func (m *SrcSetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return matchNamedSet(m.Set, pkt.SrcAddr, pkt.SrcPort, pkt.Metadata.IngressIface), nil
}

// NotSrcSetMatcher matches packets whose source-derived value is not in Set.
type NotSrcSetMatcher struct {
	Set set.Set
}

func (m *NotSrcSetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !matchNamedSet(m.Set, pkt.SrcAddr, pkt.SrcPort, pkt.Metadata.IngressIface), nil
}

// DstSetMatcher matches packets whose destination-derived value (address,
// port, or interface, depending on Set's type) is in Set.
type DstSetMatcher struct {
	Set set.Set
}

func (m *DstSetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return matchNamedSet(m.Set, pkt.DstAddr, pkt.DstPort, pkt.Metadata.EgressIface), nil
}

// NotDstSetMatcher matches packets whose destination-derived value is not in Set.
type NotDstSetMatcher struct {
	Set set.Set
}

func (m *NotDstSetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !matchNamedSet(m.Set, pkt.DstAddr, pkt.DstPort, pkt.Metadata.EgressIface), nil
}

// ConnStateMatcher matches packets whose connection-tracking state is in States.
type ConnStateMatcher struct {
	States []conntrack.State
}

func (m *ConnStateMatcher) Match(_ *packet.Packet, state conntrack.State) (bool, error) {
	return slices.Contains(m.States, state), nil
}

// NotConnStateMatcher matches packets whose connection-tracking state is not in States.
type NotConnStateMatcher struct {
	States []conntrack.State
}

func (m *NotConnStateMatcher) Match(_ *packet.Packet, state conntrack.State) (bool, error) {
	return !slices.Contains(m.States, state), nil
}

// PayloadMatcher matches packets whose payload matches Payload's pattern.
type PayloadMatcher struct {
	Payload *payload.Matcher
}

func (m *PayloadMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Payload.Match(pkt.Payload), nil
}
