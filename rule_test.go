package firecore

import (
	"fmt"
	"sync"
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/matcher"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/set"
	. "github.com/onsi/gomega"
)

func mustNew(opts ...RuleOption) *Rule {
	r, err := NewRule(opts...)
	Expect(err).NotTo(HaveOccurred())
	return r
}

func mustNewPacket(t testing.TB, opts ...packet.Option) *packet.Packet {
	t.Helper()
	pkt, err := packet.New(opts...)
	Expect(err).ToNot(HaveOccurred())
	return pkt
}

func TestWithNameEmptyFails(t *testing.T) {
	RegisterTestingT(t)

	r, err := NewRule(WithName(""))
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())
}

func TestNewRuleNilOptionFails(t *testing.T) {
	RegisterTestingT(t)

	r, err := NewRule(WithAction(Accept), nil)
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())
}

func TestRuleMatchNilPacketReturnsFalse(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(WithProto(proto.TCP), WithDstPort(80), WithAction(Accept))
	Expect(r.Match(nil)).To(BeFalse())
	Expect(r.MatchWithConntrackState(nil, conntrack.StateEstablished)).To(BeFalse())

	// A nil packet must not satisfy a negated-only condition either
	// (fail closed, not fail open).
	rNegated := mustNew(WithNotProto(proto.TCP))
	Expect(rNegated.Match(nil)).To(BeFalse())
}

func TestEmptyRule(t *testing.T) {
	RegisterTestingT(t)

	rule := mustNew()
	pkt1 := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)
	pkt2 := mustNewPacket(t,
		packet.WithSrcAddr("172.16.0.1"), packet.WithSrcPort(50000), packet.WithProto(proto.Proto(8)),
		packet.WithDstAddr("2.2.2.2"), packet.WithDstPort(9999),
	)
	pkt3 := mustNewPacket(t,
		packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
		packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
	)
	pkt4 := mustNewPacket(t,
		packet.WithSrcAddr("dead:cafe::1"), packet.WithSrcPort(30000), packet.WithProto(proto.Proto(64)),
		packet.WithDstAddr("ffff::1"), packet.WithDstPort(8080),
	)
	pkts := []*packet.Packet{pkt1, pkt2, pkt3, pkt4}
	for _, pkt := range pkts {
		t.Run(pkt.String(), func(t *testing.T) {
			Expect(rule.Match(pkt)).To(BeTrue())
		})
	}
}

func TestRuleIPFamilyMismatch(t *testing.T) {
	RegisterTestingT(t)

	// IPv6 packet
	pktV6 := mustNewPacket(t,
		packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
		packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
	)

	// Rules with IPv4 networks should not match IPv6 packets
	ipv4Rules := []*Rule{
		mustNew(WithSrcNet("10.10.10.0/24")),
		mustNew(WithDstNet("1.1.1.1/32")),
		mustNew(WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
		mustNew(WithProto(proto.UDP), WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
	}
	for i, r := range ipv4Rules {
		t.Run(fmt.Sprintf("IPv4 rule %d should not match IPv6 packet", i), func(t *testing.T) {
			Expect(r.Match(pktV6)).To(BeFalse())
		})
	}

	// IPv4 packet
	pktV4 := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)

	// Rules with IPv6 networks should not match IPv4 packets
	ipv6Rules := []*Rule{
		mustNew(WithSrcNet("dead:beef::/64")),
		mustNew(WithDstNet("cafe::/112")),
		mustNew(WithSrcNet("dead:beef::/64"), WithDstNet("cafe::/112")),
		mustNew(WithProto(proto.TCP), WithSrcNet("dead:beef::/64"), WithDstNet("cafe::/112")),
	}
	for i, r := range ipv6Rules {
		t.Run(fmt.Sprintf("IPv6 rule %d should not match IPv4 packet", i), func(t *testing.T) {
			Expect(r.Match(pktV4)).To(BeFalse())
		})
	}
}

func TestRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	pktShouldMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)
	pktShouldNotMatch := mustNewPacket(t,
		packet.WithSrcAddr("172.16.0.1"), packet.WithSrcPort(50000), packet.WithProto(proto.Proto(8)),
		packet.WithDstAddr("2.2.2.2"), packet.WithDstPort(9999),
	)
	for i, r := range makeCommonRules("10.10.10.0/24", "1.1.1.1/32", proto.UDP, 55555, 53) {
		t.Run(fmt.Sprintf("rule %d should match", i), func(t *testing.T) {
			Expect(r.Match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("rule %d should not match", i), func(t *testing.T) {
			Expect(r.Match(pktShouldNotMatch)).To(BeFalse())
		})
	}
}

func TestRuleMatchV6(t *testing.T) {
	RegisterTestingT(t)

	pktShouldMatch := mustNewPacket(t,
		packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
		packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
	)
	pktShouldNotMatch := mustNewPacket(t,
		packet.WithSrcAddr("dead:cafe::1"), packet.WithSrcPort(30000), packet.WithProto(proto.Proto(64)),
		packet.WithDstAddr("ffff::1"), packet.WithDstPort(8080),
	)
	for i, r := range makeCommonRules("dead:beef::/64", "cafe::/112", proto.TCP, 44444, 80) {
		t.Run(fmt.Sprintf("rule %d should match", i), func(t *testing.T) {
			Expect(r.Match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("rule %d should not match", i), func(t *testing.T) {
			Expect(r.Match(pktShouldNotMatch)).To(BeFalse())
		})
	}
}

func TestRuleConntrackStateMatch(t *testing.T) {
	RegisterTestingT(t)

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithSrcPort(12345),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithDstPort(80),
		packet.WithProto(proto.TCP),
	)
	r := mustNew(
		WithProto(proto.TCP),
		WithDstPort(80),
		WithConnState(conntrack.StateEstablished),
	)

	Expect(r.MatchWithConntrackState(pkt, conntrack.StateEstablished)).To(BeTrue())
	Expect(r.MatchWithConntrackState(pkt, conntrack.StateNew)).To(BeFalse())
}

func TestWithConnStateInvalidFails(t *testing.T) {
	RegisterTestingT(t)

	r, err := NewRule(WithConnState(conntrack.State("bogus")))
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())
}

func TestWithNotConnStateInvalidFails(t *testing.T) {
	RegisterTestingT(t)

	r, err := NewRule(WithNotConnState(conntrack.State("bogus")))
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())
}

func TestRuleNegatedConntrackStateMatch(t *testing.T) {
	RegisterTestingT(t)

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithSrcPort(12345),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithDstPort(80),
		packet.WithProto(proto.TCP),
	)
	r := mustNew(
		WithProto(proto.TCP),
		WithDstPort(80),
		WithNotConnState(conntrack.StateEstablished),
	)

	Expect(r.MatchWithConntrackState(pkt, conntrack.StateNew)).To(BeTrue())
	Expect(r.MatchWithConntrackState(pkt, conntrack.StateEstablished)).To(BeFalse())
}

func TestRulePayloadMatch(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(WithPayload(`GET /admin`))

	pktMatch := mustNewPacket(t, packet.WithPayload([]byte("GET /admin HTTP/1.1")))
	pktNoMatch := mustNewPacket(t, packet.WithPayload([]byte("GET /public HTTP/1.1")))

	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNewReturnsErrorOnInvalidPayloadPattern(t *testing.T) {
	RegisterTestingT(t)

	_, err := NewRule(WithPayload(`[`))
	Expect(err).To(HaveOccurred())
}

func TestActionString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		action   Action
		expected string
	}{
		{Accept, "Accept"},
		{Drop, "Drop"},
		{Pass, "Pass"},
		{Action(999), "Undefined(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			Expect(tt.action.String()).To(Equal(tt.expected))
		})
	}
}

func TestActionValidate(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name      string
		action    Action
		shouldErr bool
	}{
		{"Accept is valid", Accept, false},
		{"Drop is valid", Drop, false},
		{"Pass is valid", Pass, false},
		{"Undefined action is invalid", Action(999), true},
		{"Another undefined action is invalid", Action(-1), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action.Validate()
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func TestNewReturnsErrorOnInvalidCIDR(t *testing.T) {
	RegisterTestingT(t)

	tests := []string{
		"invalid-cidr",
		"10.10.10.1",         // Missing prefix length
		"256.256.256.256/32", // Invalid IP
		"not-an-ip/24",
	}

	for _, cidr := range tests {
		t.Run(fmt.Sprintf("should error on %s (src)", cidr), func(t *testing.T) {
			_, err := NewRule(WithSrcNet(cidr))
			Expect(err).To(HaveOccurred())
		})
		t.Run(fmt.Sprintf("should error on %s (dst)", cidr), func(t *testing.T) {
			_, err := NewRule(WithDstNet(cidr))
			Expect(err).To(HaveOccurred())
		})
	}
}

func makeCommonRules(srcNet, dstNet string, p proto.Proto, srcPort, dstPort uint16) []*Rule {
	return []*Rule{
		mustNew(WithProto(p)),
		mustNew(WithSrcPort(srcPort)),
		mustNew(WithDstPort(dstPort)),
		mustNew(WithSrcNet(srcNet)),
		mustNew(WithDstNet(dstNet)),

		mustNew(WithProto(p), WithSrcPort(srcPort)),
		mustNew(WithProto(p), WithDstPort(dstPort)),
		mustNew(WithProto(p), WithSrcNet(srcNet)),
		mustNew(WithProto(p), WithDstNet(dstNet)),

		mustNew(WithSrcPort(srcPort), WithDstPort(dstPort)),
		mustNew(WithSrcPort(srcPort), WithSrcNet(srcNet)),
		mustNew(WithSrcPort(srcPort), WithDstNet(dstNet)),

		mustNew(WithDstPort(dstPort), WithSrcNet(srcNet)),
		mustNew(WithDstPort(dstPort), WithDstNet(dstNet)),

		mustNew(WithSrcNet(srcNet), WithDstNet(dstNet)),

		mustNew(WithProto(p), WithDstPort(dstPort), WithDstNet(dstNet)),
		mustNew(WithSrcPort(srcPort), WithDstPort(dstPort), WithSrcNet(srcNet)),
		mustNew(WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),

		mustNew(WithProto(p), WithSrcPort(srcPort), WithDstPort(dstPort), WithDstNet(dstNet)),
		mustNew(WithProto(p), WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),

		mustNew(WithProto(p), WithSrcPort(srcPort), WithDstPort(dstPort), WithSrcNet(srcNet), WithDstNet(dstNet)),
	}
}

func TestParseAction(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		input     string
		expected  Action
		shouldErr bool
	}{
		{"accept", Accept, false},
		{"Accept", Accept, false},
		{"ACCEPT", Accept, false},
		{"drop", Drop, false},
		{"Drop", Drop, false},
		{"DROP", Drop, false},
		{"pass", Pass, false},
		{"Pass", Pass, false},
		{"PASS", Pass, false},
		{"invalid", Action(0), true},
		{"", Action(0), true},
		{"deny", Action(0), true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			action, err := ParseAction(tt.input)
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(action).To(Equal(tt.expected))
			}
		})
	}
}

func TestRulePacketCounter(t *testing.T) {
	RegisterTestingT(t)

	rule := mustNew(WithProto(proto.UDP), WithDstPort(53))
	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)
	pktNoMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)

	// Initially, packet count should be 0
	Expect(rule.PacketCount()).To(Equal(uint64(0)))

	// Match a packet, count should increment to 1
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.PacketCount()).To(Equal(uint64(1)))

	// Match another packet, count should increment to 2
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.PacketCount()).To(Equal(uint64(2)))

	// Non-matching packet should not increment counter
	Expect(rule.Match(pktNoMatch)).To(BeFalse())
	Expect(rule.PacketCount()).To(Equal(uint64(2)))

	// Reset counter
	rule.ResetPacketCount()
	Expect(rule.PacketCount()).To(Equal(uint64(0)))

	// Match after reset should increment from 0
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.PacketCount()).To(Equal(uint64(1)))
}

func TestRulePacketCounterConcurrency(t *testing.T) {
	RegisterTestingT(t)

	rule := mustNew(WithProto(proto.UDP), WithDstPort(53))
	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)

	// Concurrently match packets to test thread-safety
	numGoroutines := 100
	matchesPerGoroutine := 100
	expectedCount := uint64(numGoroutines * matchesPerGoroutine)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < matchesPerGoroutine; j++ {
				rule.Match(pktMatch)
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Verify the counter is correct
	Expect(rule.PacketCount()).To(Equal(expectedCount))
}

func TestRuleByteCounter(t *testing.T) {
	RegisterTestingT(t)

	rule := mustNew(WithProto(proto.UDP), WithDstPort(53))
	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
		packet.WithPayload([]byte("hi")), packet.WithSize(74),
	)
	pktNoMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
		packet.WithPayload([]byte("nope")), packet.WithSize(100),
	)

	// Initially, byte count should be 0
	Expect(rule.ByteCount()).To(Equal(uint64(0)))

	// Match a packet, byte count should increase by its full size, not its
	// (shorter, or possibly absent) payload length
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.ByteCount()).To(Equal(uint64(74)))

	// Match another packet, byte count should accumulate
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.ByteCount()).To(Equal(uint64(148)))

	// Non-matching packet should not add to the byte count
	Expect(rule.Match(pktNoMatch)).To(BeFalse())
	Expect(rule.ByteCount()).To(Equal(uint64(148)))

	// Reset counter
	rule.ResetByteCount()
	Expect(rule.ByteCount()).To(Equal(uint64(0)))

	// Match after reset should accumulate from 0
	Expect(rule.Match(pktMatch)).To(BeTrue())
	Expect(rule.ByteCount()).To(Equal(uint64(74)))
}

func TestRuleWithName(t *testing.T) {
	RegisterTestingT(t)

	// Rule without name has an empty Name
	ruleNoName := mustNew(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80))
	Expect(ruleNoName.Name).To(Equal(""))

	// Rule with name should keep it
	ruleWithName := mustNew(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80), WithName("allow-http"))
	Expect(ruleWithName.Name).To(Equal("allow-http"))

	// Setting Name directly should also work
	ruleDirectName := mustNew(WithAction(Drop))
	ruleDirectName.Name = "block-all"
	Expect(ruleDirectName.Name).To(Equal("block-all"))
}

func TestNegatedRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// Packet that will be matched against negated rules
	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)

	// Negated protocol: should NOT match proto 17, but SHOULD match everything else
	ruleNotProto := mustNew(WithNotProto(proto.UDP))
	Expect(ruleNotProto.Match(pkt)).To(BeFalse())

	ruleNotProtoOther := mustNew(WithNotProto(proto.TCP))
	Expect(ruleNotProtoOther.Match(pkt)).To(BeTrue())

	// Negated source port: should NOT match src port 55555
	ruleNotSrcPort := mustNew(WithNotSrcPort(55555))
	Expect(ruleNotSrcPort.Match(pkt)).To(BeFalse())

	ruleNotSrcPortOther := mustNew(WithNotSrcPort(12345))
	Expect(ruleNotSrcPortOther.Match(pkt)).To(BeTrue())

	// Negated destination port: should NOT match dst port 53
	ruleNotDstPort := mustNew(WithNotDstPort(53))
	Expect(ruleNotDstPort.Match(pkt)).To(BeFalse())

	ruleNotDstPortOther := mustNew(WithNotDstPort(80))
	Expect(ruleNotDstPortOther.Match(pkt)).To(BeTrue())

	// Negated source network: should NOT match 10.10.10.0/24
	ruleNotSrcNet := mustNew(WithNotSrcNet("10.10.10.0/24"))
	Expect(ruleNotSrcNet.Match(pkt)).To(BeFalse())

	ruleNotSrcNetOther := mustNew(WithNotSrcNet("192.168.0.0/16"))
	Expect(ruleNotSrcNetOther.Match(pkt)).To(BeTrue())

	// Negated destination network: should NOT match 1.1.1.1/32
	ruleNotDstNet := mustNew(WithNotDstNet("1.1.1.1/32"))
	Expect(ruleNotDstNet.Match(pkt)).To(BeFalse())

	ruleNotDstNetOther := mustNew(WithNotDstNet("2.2.2.2/32"))
	Expect(ruleNotDstNetOther.Match(pkt)).To(BeTrue())
}

func TestNegatedRuleConfig(t *testing.T) {
	RegisterTestingT(t)

	// Valid negated rule — negated options wrap a shared matcher type in
	// matcher.Negated rather than using a dedicated Not* type.
	rule := mustNew(
		WithAction(Accept),
		WithNotProto(proto.TCP),
		WithNotSrcPort(80),
		WithNotDstPort(443),
		WithNotSrcNet("10.0.0.0/8"),
		WithNotDstNet("192.168.0.0/16"),
	)
	_, ok := findMatcher[*matcher.ProtoMatcher](rule, true)
	Expect(ok).To(BeTrue())
	_, ok = findSrcSet(rule, true, set.TypePort)
	Expect(ok).To(BeTrue())
	_, ok = findDstSet(rule, true, set.TypePort)
	Expect(ok).To(BeTrue())
	_, ok = findSrcSet(rule, true, set.TypeIP)
	Expect(ok).To(BeTrue())
	_, ok = findDstSet(rule, true, set.TypeIP)
	Expect(ok).To(BeTrue())
	// Positive (non-negated) matchers should be absent when only negated
	// values are specified.
	_, ok = findMatcher[*matcher.ProtoMatcher](rule, false)
	Expect(ok).To(BeFalse())
	_, ok = findSrcSet(rule, false, set.TypePort)
	Expect(ok).To(BeFalse())
	_, ok = findDstSet(rule, false, set.TypePort)
	Expect(ok).To(BeFalse())
	_, ok = findSrcSet(rule, false, set.TypeIP)
	Expect(ok).To(BeFalse())
	_, ok = findDstSet(rule, false, set.TypeIP)
	Expect(ok).To(BeFalse())

	// Positive and negated matchers can be combined on the same rule
	ruleCombined := mustNew(
		WithAction(Accept),
		WithProto(proto.UDP),
		WithNotProto(proto.TCP),
		WithSrcPort(12345),
		WithNotSrcPort(80),
		WithDstPort(53),
		WithNotDstPort(443),
		WithSrcNet("10.0.0.0/8"),
		WithNotSrcNet("10.10.0.0/16"),
		WithDstNet("1.1.1.0/24"),
		WithNotDstNet("1.1.1.100/32"),
	)
	_, ok = findMatcher[*matcher.ProtoMatcher](ruleCombined, false)
	Expect(ok).To(BeTrue())
	_, ok = findMatcher[*matcher.ProtoMatcher](ruleCombined, true)
	Expect(ok).To(BeTrue())
	_, ok = findSrcSet(ruleCombined, false, set.TypePort)
	Expect(ok).To(BeTrue())
	_, ok = findSrcSet(ruleCombined, true, set.TypePort)
	Expect(ok).To(BeTrue())
	_, ok = findDstSet(ruleCombined, false, set.TypePort)
	Expect(ok).To(BeTrue())
	_, ok = findDstSet(ruleCombined, true, set.TypePort)
	Expect(ok).To(BeTrue())
	_, ok = findSrcSet(ruleCombined, false, set.TypeIP)
	Expect(ok).To(BeTrue())
	_, ok = findSrcSet(ruleCombined, true, set.TypeIP)
	Expect(ok).To(BeTrue())
	_, ok = findDstSet(ruleCombined, false, set.TypeIP)
	Expect(ok).To(BeTrue())
	_, ok = findDstSet(ruleCombined, true, set.TypeIP)
	Expect(ok).To(BeTrue())
}

func TestCombinedPositiveAndNegativeRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// Rule matches src in 10.0.0.0/8 but NOT in 10.10.0.0/16
	rule := mustNew(WithSrcNet("10.0.0.0/8"), WithNotSrcNet("10.10.0.0/16"))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	pktMatch := mustNewPacket(t, packet.WithSrcAddr("10.1.2.3"))
	Expect(rule.Match(pktMatch)).To(BeTrue())

	// In 10.0.0.0/8 AND in 10.10.0.0/16 → should not match (excluded by neg)
	pktNotHit := mustNewPacket(t, packet.WithSrcAddr("10.10.0.5"))
	Expect(rule.Match(pktNotHit)).To(BeFalse())

	// Not in 10.0.0.0/8 at all → should not match (excluded by positive)
	pktOutside := mustNewPacket(t, packet.WithSrcAddr("172.16.0.1"))
	Expect(rule.Match(pktOutside)).To(BeFalse())

	// Rule matches proto 17 AND NOT proto 6 (proto 6 is excluded, proto 17 is required)
	ruleProto := mustNew(WithProto(proto.UDP), WithNotProto(proto.TCP))
	pktProto17 := mustNewPacket(t, packet.WithProto(proto.UDP))
	pktProto6 := mustNewPacket(t, packet.WithProto(proto.TCP))
	pktProto1 := mustNewPacket(t, packet.WithProto(proto.ICMP))
	Expect(ruleProto.Match(pktProto17)).To(BeTrue())
	Expect(ruleProto.Match(pktProto6)).To(BeFalse())
	Expect(ruleProto.Match(pktProto1)).To(BeFalse()) // not in positive set
}

func TestWithSetNilFails(t *testing.T) {
	RegisterTestingT(t)

	r, err := NewRule(WithSrcSet(nil))
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())

	r, err = NewRule(WithNotSrcSet(nil))
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())

	r, err = NewRule(WithDstSet(nil))
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())

	r, err = NewRule(WithNotDstSet(nil))
	Expect(err).To(HaveOccurred())
	Expect(r).To(BeNil())
}

func TestNamedSetRuleMatchWithNamedPortString(t *testing.T) {
	RegisterTestingT(t)

	// Build a port set using well-known port names as strings.
	portSet := set.NewPortSet()
	_ = portSet.Add("http")
	_ = portSet.Add("https")

	pktHTTP := mustNewPacket(t, packet.WithDstPort(80))
	pktHTTPS := mustNewPacket(t, packet.WithDstPort(443))
	pktOther := mustNewPacket(t, packet.WithDstPort(8080))

	r := mustNew(WithDstSet(portSet))
	Expect(r.Match(pktHTTP)).To(BeTrue())
	Expect(r.Match(pktHTTPS)).To(BeTrue())
	Expect(r.Match(pktOther)).To(BeFalse())
}

func TestNamedSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("10.0.0.0/8")

	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(80))

	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)
	pktNoMatchIP := mustNewPacket(t,
		packet.WithSrcAddr("192.168.1.1"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)
	pktNoMatchPort := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	)

	r := mustNew(WithSrcSet(ipSet), WithDstSet(portSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatchIP)).To(BeFalse())
	Expect(r.Match(pktNoMatchPort)).To(BeFalse())
}

func TestNamedSetRuleMatchDstIPSet(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("1.1.1.0/24")

	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("1.1.1.1"),
	)
	pktNoMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("2.2.2.2"),
	)

	r := mustNew(WithDstSet(ipSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNamedSetRuleMatchSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(55555))

	pktMatch := mustNewPacket(t,
		packet.WithSrcPort(55555),
	)
	pktNoMatch := mustNewPacket(t,
		packet.WithSrcPort(12345),
	)

	r := mustNew(WithSrcSet(portSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNegatedNamedSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// NotSrcIPSet: packets whose source is in the set should NOT match.
	srcIPSet := set.NewIPSet()
	_ = srcIPSet.Add("10.0.0.0/8")

	rNegSrc := mustNew(WithNotSrcSet(srcIPSet))
	pktInSet := mustNewPacket(t, packet.WithSrcAddr("10.1.2.3"))
	pktOutSet := mustNewPacket(t, packet.WithSrcAddr("192.168.1.1"))
	Expect(rNegSrc.Match(pktInSet)).To(BeFalse())
	Expect(rNegSrc.Match(pktOutSet)).To(BeTrue())

	// NotDstIPSet: packets whose destination is in the set should NOT match.
	dstIPSet := set.NewIPSet()
	_ = dstIPSet.Add("1.1.1.0/24")

	rNegDst := mustNew(WithNotDstSet(dstIPSet))
	pktDstIn := mustNewPacket(t, packet.WithDstAddr("1.1.1.1"))
	pktDstOut := mustNewPacket(t, packet.WithDstAddr("2.2.2.2"))
	Expect(rNegDst.Match(pktDstIn)).To(BeFalse())
	Expect(rNegDst.Match(pktDstOut)).To(BeTrue())

	// NotSrcPortSet: packets whose source port is in the set should NOT match.
	srcPortSet := set.NewPortSet()
	_ = srcPortSet.Add(uint16(55555))

	rNotSrcPort := mustNew(WithNotSrcSet(srcPortSet))
	pktSrcPortIn := mustNewPacket(t, packet.WithSrcPort(55555))
	pktSrcPortOut := mustNewPacket(t, packet.WithSrcPort(12345))
	Expect(rNotSrcPort.Match(pktSrcPortIn)).To(BeFalse())
	Expect(rNotSrcPort.Match(pktSrcPortOut)).To(BeTrue())

	// NotDstPortSet: packets whose destination port is in the set should NOT match.
	dstPortSet := set.NewPortSet()
	_ = dstPortSet.Add(uint16(80))

	rNotDstPort := mustNew(WithNotDstSet(dstPortSet))
	pktDstPortIn := mustNewPacket(t, packet.WithDstPort(80))
	pktDstPortOut := mustNewPacket(t, packet.WithDstPort(443))
	Expect(rNotDstPort.Match(pktDstPortIn)).To(BeFalse())
	Expect(rNotDstPort.Match(pktDstPortOut)).To(BeTrue())
}

func TestCombinedPositiveAndNegativeNamedSetMatch(t *testing.T) {
	RegisterTestingT(t)

	// Match src in 10.0.0.0/8 named set but NOT in 10.10.0.0/16 named set.
	posSet := set.NewIPSet()
	_ = posSet.Add("10.0.0.0/8")

	negSet := set.NewIPSet()
	_ = negSet.Add("10.10.0.0/16")

	r := mustNew(WithSrcSet(posSet), WithNotSrcSet(negSet))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	pktMatch := mustNewPacket(t, packet.WithSrcAddr("10.1.2.3"))
	Expect(r.Match(pktMatch)).To(BeTrue())
	// In 10.0.0.0/8 AND in 10.10.0.0/16 → excluded by neg
	pktNotHit := mustNewPacket(t, packet.WithSrcAddr("10.10.0.5"))
	Expect(r.Match(pktNotHit)).To(BeFalse())
	// Not in 10.0.0.0/8 at all → excluded by positive
	pktOutside := mustNewPacket(t, packet.WithSrcAddr("172.16.0.1"))
	Expect(r.Match(pktOutside)).To(BeFalse())
}

func TestIPPortSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	srcSet := set.NewIPPortSet()
	_ = srcSet.Add("10.0.0.0/8,1000-2000")
	dstSet := set.NewIPPortSet()
	_ = dstSet.Add("1.1.1.1,443")

	r := mustNew(WithSrcSet(srcSet), WithDstSet(dstSet))

	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(1500), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	)
	Expect(r.Match(pktMatch)).To(BeTrue())

	pktNoMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(999), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	)
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNegatedIPPortSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	negSet := set.NewIPPortSet()
	_ = negSet.Add("10.0.0.0/8,53")

	r := mustNew(WithNotSrcSet(negSet), WithNotDstSet(negSet))

	// src port 53 and dst port 53 both in set → not matched
	pkt1 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(53), packet.WithProto(proto.UDP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	)
	Expect(r.Match(pkt1)).To(BeFalse())

	// src 10.1.2.3:53 is excluded; any protocol is excluded now
	pkt2 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(53), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	)
	Expect(r.Match(pkt2)).To(BeFalse())

	// src port not in set → src passes; dst also excluded → not matched
	pkt3 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(80), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	)
	Expect(r.Match(pkt3)).To(BeFalse())

	// neither src nor dst in set → matched
	pkt4 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(80), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(80),
	)
	Expect(r.Match(pkt4)).To(BeTrue())
}

func TestIngressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"))

	// Rule matches only eth0
	r := mustNew(WithSrcIface("eth0"))
	Expect(r.Match(pktEth0)).To(BeTrue())
	Expect(r.Match(pktEth1)).To(BeFalse())
	Expect(r.Match(pktNoIface)).To(BeFalse())

	// Rule matches eth0 or eth1
	rMulti := mustNew(WithSrcIface("eth0"), WithSrcIface("eth1"))
	Expect(rMulti.Match(pktEth0)).To(BeTrue())
	Expect(rMulti.Match(pktEth1)).To(BeTrue())
	Expect(rMulti.Match(pktNoIface)).To(BeFalse())

	// Rule with no interface constraint matches all
	rAny := mustNew()
	Expect(rAny.Match(pktEth0)).To(BeTrue())
	Expect(rAny.Match(pktNoIface)).To(BeTrue())
}

func TestNotIngressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"))

	// Rule excludes eth0
	r := mustNew(WithNotSrcIface("eth0"))
	Expect(r.Match(pktEth0)).To(BeFalse())
	Expect(r.Match(pktEth1)).To(BeTrue())
	Expect(r.Match(pktNoIface)).To(BeTrue())
}

func TestIngressIfaceAndNotIngressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktEth2 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"), packet.WithIngressIface("eth2"))

	// Allow eth0 and eth1, but not eth1 (net effect: only eth0)
	r := mustNew(WithSrcIface("eth0"), WithSrcIface("eth1"), WithNotSrcIface("eth1"))
	Expect(r.Match(pktEth0)).To(BeTrue())
	Expect(r.Match(pktEth1)).To(BeFalse())
	Expect(r.Match(pktEth2)).To(BeFalse())
}

func TestEgressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"))

	// Rule matches only eth0
	r := mustNew(WithDstIface("eth0"))
	Expect(r.Match(pktEth0)).To(BeTrue())
	Expect(r.Match(pktEth1)).To(BeFalse())
	Expect(r.Match(pktNoIface)).To(BeFalse())

	// Rule matches eth0 or eth1
	rMulti := mustNew(WithDstIface("eth0"), WithDstIface("eth1"))
	Expect(rMulti.Match(pktEth0)).To(BeTrue())
	Expect(rMulti.Match(pktEth1)).To(BeTrue())
	Expect(rMulti.Match(pktNoIface)).To(BeFalse())

	// Rule with no interface constraint matches all
	rAny := mustNew()
	Expect(rAny.Match(pktEth0)).To(BeTrue())
	Expect(rAny.Match(pktNoIface)).To(BeTrue())
}

func TestNotEgressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"))

	// Rule excludes eth0
	r := mustNew(WithNotDstIface("eth0"))
	Expect(r.Match(pktEth0)).To(BeFalse())
	Expect(r.Match(pktEth1)).To(BeTrue())
	Expect(r.Match(pktNoIface)).To(BeTrue())
}

func TestEgressIfaceAndNotEgressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktEth2 := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"), packet.WithEgressIface("eth2"))

	// Allow eth0 and eth1, but not eth1 (net effect: only eth0)
	r := mustNew(WithDstIface("eth0"), WithDstIface("eth1"), WithNotDstIface("eth1"))
	Expect(r.Match(pktEth0)).To(BeTrue())
	Expect(r.Match(pktEth1)).To(BeFalse())
	Expect(r.Match(pktEth2)).To(BeFalse())
}

func TestIfaceSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	ifaceSet := set.NewIfaceSet()
	_ = ifaceSet.Add("eth0")
	_ = ifaceSet.Add("eth1")

	pktIngressEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktIngressEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktIngressEth2 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"), packet.WithIngressIface("eth2"))
	pktNoIface := mustNewPacket(t, packet.WithSrcAddr("10.0.0.4"))

	// IfaceSet on Source — matches against ingress iface.
	rSrc := mustNew(WithSrcSet(ifaceSet))
	Expect(rSrc.Match(pktIngressEth0)).To(BeTrue())
	Expect(rSrc.Match(pktIngressEth1)).To(BeTrue())
	Expect(rSrc.Match(pktIngressEth2)).To(BeFalse())
	Expect(rSrc.Match(pktNoIface)).To(BeFalse())

	pktEgressEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEgressEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktEgressEth2 := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"), packet.WithEgressIface("eth2"))

	// IfaceSet on Destination — matches against egress iface.
	rDst := mustNew(WithDstSet(ifaceSet))
	Expect(rDst.Match(pktEgressEth0)).To(BeTrue())
	Expect(rDst.Match(pktEgressEth1)).To(BeTrue())
	Expect(rDst.Match(pktEgressEth2)).To(BeFalse())
}

func TestNotIfaceSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	ifaceSet := set.NewIfaceSet()
	_ = ifaceSet.Add("eth0")

	pktIngressEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktIngressEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))

	// NotSrcIfaceSet: packets on ingress eth0 should NOT match.
	rNotSrc := mustNew(WithNotSrcSet(ifaceSet))
	Expect(rNotSrc.Match(pktIngressEth0)).To(BeFalse())
	Expect(rNotSrc.Match(pktIngressEth1)).To(BeTrue())

	pktEgressEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEgressEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))

	// NotDstIfaceSet: packets on egress eth0 should NOT match.
	rNotDst := mustNew(WithNotDstSet(ifaceSet))
	Expect(rNotDst.Match(pktEgressEth0)).To(BeFalse())
	Expect(rNotDst.Match(pktEgressEth1)).To(BeTrue())
}
