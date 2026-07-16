package matcher

import (
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/set"
)

// The old* types below reproduce the pre-consolidation matcher shape (one
// dedicated struct per field, with negation hand-written into a duplicate
// Not* type) so the dispatch cost of that design can be benchmarked directly
// against the current SrcSetMatcher/DstSetMatcher + Negated design.

type oldSrcPortMatcher struct {
	Ports *set.PortSet
}

func (m *oldSrcPortMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Ports.Match(pkt.SrcPort), nil
}

type oldNotSrcPortMatcher struct {
	Ports *set.PortSet
}

func (m *oldNotSrcPortMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Ports.Match(pkt.SrcPort), nil
}

type oldSrcNetMatcher struct {
	Nets *set.IPSet
}

func (m *oldSrcNetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return m.Nets.Match(pkt.SrcAddr), nil
}

type oldNotSrcNetMatcher struct {
	Nets *set.IPSet
}

func (m *oldNotSrcNetMatcher) Match(pkt *packet.Packet, _ conntrack.State) (bool, error) {
	return !m.Nets.Match(pkt.SrcAddr), nil
}

func mustPacket(b *testing.B, opts ...packet.PacketOption) *packet.Packet {
	b.Helper()
	pkt, err := packet.New(opts...)
	if err != nil {
		b.Fatalf("packet.New: %v", err)
	}
	return pkt
}

// Port matcher: old direct-field-access dispatch vs new Set.Type()-switch dispatch.

func BenchmarkSrcPortMatch_Old(b *testing.B) {
	ports := set.NewPortSet()
	_ = ports.Add(uint16(80))
	_ = ports.Add(uint16(443))
	m := &oldSrcPortMatcher{Ports: ports}
	pkt := mustPacket(b, packet.WithSrcPort(443))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}

func BenchmarkSrcPortMatch_New(b *testing.B) {
	ports := set.NewPortSet()
	_ = ports.Add(uint16(80))
	_ = ports.Add(uint16(443))
	m := &SrcSetMatcher{Set: ports}
	pkt := mustPacket(b, packet.WithSrcPort(443))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}

// Negated port matcher: old hand-written negation vs new generic Negated wrapper.

func BenchmarkNotSrcPortMatch_Old(b *testing.B) {
	ports := set.NewPortSet()
	_ = ports.Add(uint16(80))
	m := &oldNotSrcPortMatcher{Ports: ports}
	pkt := mustPacket(b, packet.WithSrcPort(443))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}

func BenchmarkNotSrcPortMatch_New(b *testing.B) {
	ports := set.NewPortSet()
	_ = ports.Add(uint16(80))
	m := Negate(&SrcSetMatcher{Set: ports})
	pkt := mustPacket(b, packet.WithSrcPort(443))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}

// Net matcher: same comparison, on the IPSet path instead of PortSet.

func BenchmarkSrcNetMatch_Old(b *testing.B) {
	nets := set.NewIPSet()
	_ = nets.Add("10.0.0.0/8")
	m := &oldSrcNetMatcher{Nets: nets}
	pkt := mustPacket(b, packet.WithSrcAddr("10.1.2.3"))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}

func BenchmarkSrcNetMatch_New(b *testing.B) {
	nets := set.NewIPSet()
	_ = nets.Add("10.0.0.0/8")
	m := &SrcSetMatcher{Set: nets}
	pkt := mustPacket(b, packet.WithSrcAddr("10.1.2.3"))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}

func BenchmarkNotSrcNetMatch_Old(b *testing.B) {
	nets := set.NewIPSet()
	_ = nets.Add("10.0.0.0/8")
	m := &oldNotSrcNetMatcher{Nets: nets}
	pkt := mustPacket(b, packet.WithSrcAddr("10.1.2.3"))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}

func BenchmarkNotSrcNetMatch_New(b *testing.B) {
	nets := set.NewIPSet()
	_ = nets.Add("10.0.0.0/8")
	m := Negate(&SrcSetMatcher{Set: nets})
	pkt := mustPacket(b, packet.WithSrcAddr("10.1.2.3"))

	for b.Loop() {
		_, _ = m.Match(pkt, conntrack.StateNew)
	}
}
