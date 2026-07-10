package rule

import (
	"fmt"
	"sync"
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/set"
	. "github.com/onsi/gomega"
)

func mustNew(opts ...RuleOption) *Rule {
	r, err := New(opts...)
	Expect(err).NotTo(HaveOccurred())
	return r
}

func TestEmptyRule(t *testing.T) {
	RegisterTestingT(t)

	rule := mustNew()
	pkts := []*packet.Packet{
		packet.New(
			packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
			packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
		),
		packet.New(
			packet.WithSrcAddr("172.16.0.1"), packet.WithSrcPort(50000), packet.WithProto(proto.Proto(8)),
			packet.WithDstAddr("2.2.2.2"), packet.WithDstPort(9999),
		),
		packet.New(
			packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
			packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
		),
		packet.New(
			packet.WithSrcAddr("dead:cafe::1"), packet.WithSrcPort(30000), packet.WithProto(proto.Proto(64)),
			packet.WithDstAddr("ffff::1"), packet.WithDstPort(8080),
		),
	}
	for _, pkt := range pkts {
		t.Run(pkt.String(), func(t *testing.T) {
			Expect(rule.Match(pkt)).To(BeTrue())
		})
	}
}

func TestRuleIPFamilyMismatch(t *testing.T) {
	RegisterTestingT(t)

	// IPv6 packet
	pktV6 := packet.New(
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
	for _, r := range ipv4Rules {
		t.Run(fmt.Sprintf("IPv4 rule %v should not match IPv6 packet", r.String()), func(t *testing.T) {
			Expect(r.Match(pktV6)).To(BeFalse())
		})
	}

	// IPv4 packet
	pktV4 := packet.New(
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
	for _, r := range ipv6Rules {
		t.Run(fmt.Sprintf("IPv6 rule %v should not match IPv4 packet", r.String()), func(t *testing.T) {
			Expect(r.Match(pktV4)).To(BeFalse())
		})
	}
}

func TestRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	pktShouldMatch := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)
	pktShouldNotMatch := packet.New(
		packet.WithSrcAddr("172.16.0.1"), packet.WithSrcPort(50000), packet.WithProto(proto.Proto(8)),
		packet.WithDstAddr("2.2.2.2"), packet.WithDstPort(9999),
	)
	for _, r := range makeCommonRules("10.10.10.0/24", "1.1.1.1/32", proto.UDP, 55555, 53) {
		t.Run(fmt.Sprintf("should match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("should not match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldNotMatch)).To(BeFalse())
		})
	}
}

func TestRuleMatchV6(t *testing.T) {
	RegisterTestingT(t)

	pktShouldMatch := packet.New(
		packet.WithSrcAddr("dead:beef::1"), packet.WithSrcPort(44444), packet.WithProto(proto.TCP),
		packet.WithDstAddr("cafe::1"), packet.WithDstPort(80),
	)
	pktShouldNotMatch := packet.New(
		packet.WithSrcAddr("dead:cafe::1"), packet.WithSrcPort(30000), packet.WithProto(proto.Proto(64)),
		packet.WithDstAddr("ffff::1"), packet.WithDstPort(8080),
	)
	for _, r := range makeCommonRules("dead:beef::/64", "cafe::/112", proto.TCP, 44444, 80) {
		t.Run(fmt.Sprintf("should match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldMatch)).To(BeTrue())
		})
		t.Run(fmt.Sprintf("should not match %v", r.String()), func(t *testing.T) {
			Expect(r.Match(pktShouldNotMatch)).To(BeFalse())
		})
	}
}

func TestRuleConntrackStateMatch(t *testing.T) {
	RegisterTestingT(t)

	pkt := packet.New(
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

func TestRuleNegatedConntrackStateMatch(t *testing.T) {
	RegisterTestingT(t)

	pkt := packet.New(
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

func TestRuleMatchConditionsIncludeConntrackState(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(
		WithConnState(conntrack.StateNew),
		WithNotConnState(conntrack.StateEstablished),
	)

	Expect(r.MatchConditions()).To(ContainSubstring("ct_state=new,!established"))
}

func TestRulePayloadMatch(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(WithPayload(`GET /admin`))

	pktMatch := packet.New(packet.WithPayload([]byte("GET /admin HTTP/1.1")))
	pktNoMatch := packet.New(packet.WithPayload([]byte("GET /public HTTP/1.1")))

	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestRulePayloadString(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(WithAction(Accept), WithPayload(`GET /admin`))

	Expect(r.String()).To(Equal(`Accept *{*:*->*:*} payload~="GET /admin"`))
}

func TestNewReturnsErrorOnInvalidPayloadPattern(t *testing.T) {
	RegisterTestingT(t)

	_, err := New(WithPayload(`[`))
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
			_, err := New(WithSrcNet(cidr))
			Expect(err).To(HaveOccurred())
		})
		t.Run(fmt.Sprintf("should error on %s (dst)", cidr), func(t *testing.T) {
			_, err := New(WithDstNet(cidr))
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
	pktMatch := packet.New(
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)
	pktNoMatch := packet.New(
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
	pktMatch := packet.New(
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

func TestRuleWithName(t *testing.T) {
	RegisterTestingT(t)

	// Rule without name should use the full rule representation
	ruleNoName := mustNew(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80))
	Expect(ruleNoName.String()).To(Equal("Accept tcp{*:*->*:80}"))

	// Rule with name should use the name for output
	ruleWithName := mustNew(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80), WithName("allow-http"))
	Expect(ruleWithName.String()).To(Equal("allow-http"))

	// Setting Name directly should also work
	ruleDirectName := mustNew(WithAction(Drop))
	ruleDirectName.Name = "block-all"
	Expect(ruleDirectName.String()).To(Equal("block-all"))
}

func TestNegatedRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// Packet that will be matched against negated rules
	pkt := packet.New(
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

func TestNegatedRuleString(t *testing.T) {
	RegisterTestingT(t)

	// Negated proto should show with ! prefix
	ruleNotProto := mustNew(WithAction(Accept), WithNotProto(proto.TCP))
	Expect(ruleNotProto.String()).To(Equal("Accept !tcp{*:*->*:*}"))

	// Negated src port should show with ! prefix
	ruleNotSrcPort := mustNew(WithAction(Drop), WithNotSrcPort(80))
	Expect(ruleNotSrcPort.String()).To(Equal("Drop *{*:!80->*:*}"))

	// Negated dst port should show with ! prefix
	ruleNotDstPort := mustNew(WithAction(Accept), WithNotDstPort(53))
	Expect(ruleNotDstPort.String()).To(Equal("Accept *{*:*->*:!53}"))

	// Negated src net should show with ! prefix
	ruleNotSrcNet := mustNew(WithAction(Drop), WithNotSrcNet("10.0.0.0/8"))
	Expect(ruleNotSrcNet.String()).To(Equal("Drop *{!10.0.0.0/8:*->*:*}"))

	// Negated dst net should show with ! prefix
	ruleNotDstNet := mustNew(WithAction(Accept), WithNotDstNet("1.1.1.1/32"))
	Expect(ruleNotDstNet.String()).To(Equal("Accept *{*:*->!1.1.1.1/32:*}"))
}

func TestNegatedRuleConfig(t *testing.T) {
	RegisterTestingT(t)

	// Valid negated rule — negated fields populate dedicated Rule fields
	rule := mustNew(
		WithAction(Accept),
		WithNotProto(proto.TCP),
		WithNotSrcPort(80),
		WithNotDstPort(443),
		WithNotSrcNet("10.0.0.0/8"),
		WithNotDstNet("192.168.0.0/16"),
	)
	Expect(rule.NotProto).ToNot(BeNil())
	Expect(rule.NotSource.Port).ToNot(BeNil())
	Expect(rule.NotDestination.Port).ToNot(BeNil())
	Expect(rule.NotSource.Net).ToNot(BeNil())
	Expect(rule.NotDestination.Net).ToNot(BeNil())
	// Positive fields should be nil when only negated values are specified
	Expect(rule.Proto).To(BeNil())
	Expect(rule.Source.Port).To(BeNil())
	Expect(rule.Destination.Port).To(BeNil())
	Expect(rule.Source.Net).To(BeNil())
	Expect(rule.Destination.Net).To(BeNil())

	// Positive and negated fields can be combined on the same rule
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
	Expect(ruleCombined.Proto).ToNot(BeNil())
	Expect(ruleCombined.NotProto).ToNot(BeNil())
	Expect(ruleCombined.Source.Port).ToNot(BeNil())
	Expect(ruleCombined.NotSource.Port).ToNot(BeNil())
	Expect(ruleCombined.Destination.Port).ToNot(BeNil())
	Expect(ruleCombined.NotDestination.Port).ToNot(BeNil())
	Expect(ruleCombined.Source.Net).ToNot(BeNil())
	Expect(ruleCombined.NotSource.Net).ToNot(BeNil())
	Expect(ruleCombined.Destination.Net).ToNot(BeNil())
	Expect(ruleCombined.NotDestination.Net).ToNot(BeNil())
}

func TestCombinedPositiveAndNegativeRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// Rule matches src in 10.0.0.0/8 but NOT in 10.10.0.0/16
	rule := mustNew(WithSrcNet("10.0.0.0/8"), WithNotSrcNet("10.10.0.0/16"))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	pktMatch := packet.New(packet.WithSrcAddr("10.1.2.3"))
	Expect(rule.Match(pktMatch)).To(BeTrue())

	// In 10.0.0.0/8 AND in 10.10.0.0/16 → should not match (excluded by neg)
	pktNotHit := packet.New(packet.WithSrcAddr("10.10.0.5"))
	Expect(rule.Match(pktNotHit)).To(BeFalse())

	// Not in 10.0.0.0/8 at all → should not match (excluded by positive)
	pktOutside := packet.New(packet.WithSrcAddr("172.16.0.1"))
	Expect(rule.Match(pktOutside)).To(BeFalse())

	// Rule matches proto 17 AND NOT proto 6 (proto 6 is excluded, proto 17 is required)
	ruleProto := mustNew(WithProto(proto.UDP), WithNotProto(proto.TCP))
	pktProto17 := packet.New(packet.WithProto(proto.UDP))
	pktProto6 := packet.New(packet.WithProto(proto.TCP))
	pktProto1 := packet.New(packet.WithProto(proto.ICMP))
	Expect(ruleProto.Match(pktProto17)).To(BeTrue())
	Expect(ruleProto.Match(pktProto6)).To(BeFalse())
	Expect(ruleProto.Match(pktProto1)).To(BeFalse()) // not in positive set
}

func TestCombinedRuleString(t *testing.T) {
	RegisterTestingT(t)

	// Combined proto field
	ruleBoth := mustNew(WithAction(Accept), WithProto(proto.UDP), WithNotProto(proto.TCP))
	Expect(ruleBoth.String()).To(Equal("Accept udp,!tcp{*:*->*:*}"))

	// Combined src net field
	ruleSrcNet := mustNew(WithAction(Drop), WithSrcNet("10.0.0.0/8"), WithNotSrcNet("10.10.0.0/16"))
	Expect(ruleSrcNet.String()).To(Equal("Drop *{10.0.0.0/8,!10.10.0.0/16:*->*:*}"))
}

func TestNamedSetRuleMatchWithNamedPortString(t *testing.T) {
	RegisterTestingT(t)

	// Build a port set using well-known port names as strings.
	portSet := set.NewPortSet()
	_ = portSet.Add("http")
	_ = portSet.Add("https")

	pktHTTP := packet.New(packet.WithDstPort(80))
	pktHTTPS := packet.New(packet.WithDstPort(443))
	pktOther := packet.New(packet.WithDstPort(8080))

	r := mustNew(WithDstPortSet(portSet))
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

	pktMatch := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)
	pktNoMatchIP := packet.New(
		packet.WithSrcAddr("192.168.1.1"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(80),
	)
	pktNoMatchPort := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(55555), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	)

	r := mustNew(WithSrcIPSet(ipSet), WithDstPortSet(portSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatchIP)).To(BeFalse())
	Expect(r.Match(pktNoMatchPort)).To(BeFalse())
}

func TestNamedSetRuleMatchDstIPSet(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("1.1.1.0/24")

	pktMatch := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("1.1.1.1"),
	)
	pktNoMatch := packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("2.2.2.2"),
	)

	r := mustNew(WithDstIPSet(ipSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNamedSetRuleMatchSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(55555))

	pktMatch := packet.New(
		packet.WithSrcPort(55555),
	)
	pktNoMatch := packet.New(
		packet.WithSrcPort(12345),
	)

	r := mustNew(WithSrcPortSet(portSet))
	Expect(r.Match(pktMatch)).To(BeTrue())
	Expect(r.Match(pktNoMatch)).To(BeFalse())
}

func TestNegatedNamedSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	// NotSrcIPSet: packets whose source is in the set should NOT match.
	srcIPSet := set.NewIPSet()
	_ = srcIPSet.Add("10.0.0.0/8")

	rNegSrc := mustNew(WithNotSrcIPSet(srcIPSet))
	pktInSet := packet.New(packet.WithSrcAddr("10.1.2.3"))
	pktOutSet := packet.New(packet.WithSrcAddr("192.168.1.1"))
	Expect(rNegSrc.Match(pktInSet)).To(BeFalse())
	Expect(rNegSrc.Match(pktOutSet)).To(BeTrue())

	// NotDstIPSet: packets whose destination is in the set should NOT match.
	dstIPSet := set.NewIPSet()
	_ = dstIPSet.Add("1.1.1.0/24")

	rNegDst := mustNew(WithNotDstIPSet(dstIPSet))
	pktDstIn := packet.New(packet.WithDstAddr("1.1.1.1"))
	pktDstOut := packet.New(packet.WithDstAddr("2.2.2.2"))
	Expect(rNegDst.Match(pktDstIn)).To(BeFalse())
	Expect(rNegDst.Match(pktDstOut)).To(BeTrue())

	// NotSrcPortSet: packets whose source port is in the set should NOT match.
	srcPortSet := set.NewPortSet()
	_ = srcPortSet.Add(uint16(55555))

	rNotSrcPort := mustNew(WithNotSrcPortSet(srcPortSet))
	pktSrcPortIn := packet.New(packet.WithSrcPort(55555))
	pktSrcPortOut := packet.New(packet.WithSrcPort(12345))
	Expect(rNotSrcPort.Match(pktSrcPortIn)).To(BeFalse())
	Expect(rNotSrcPort.Match(pktSrcPortOut)).To(BeTrue())

	// NotDstPortSet: packets whose destination port is in the set should NOT match.
	dstPortSet := set.NewPortSet()
	_ = dstPortSet.Add(uint16(80))

	rNotDstPort := mustNew(WithNotDstPortSet(dstPortSet))
	pktDstPortIn := packet.New(packet.WithDstPort(80))
	pktDstPortOut := packet.New(packet.WithDstPort(443))
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

	r := mustNew(WithSrcIPSet(posSet), WithNotSrcIPSet(negSet))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	Expect(r.Match(packet.New(packet.WithSrcAddr("10.1.2.3")))).To(BeTrue())
	// In 10.0.0.0/8 AND in 10.10.0.0/16 → excluded by neg
	Expect(r.Match(packet.New(packet.WithSrcAddr("10.10.0.5")))).To(BeFalse())
	// Not in 10.0.0.0/8 at all → excluded by positive
	Expect(r.Match(packet.New(packet.WithSrcAddr("172.16.0.1")))).To(BeFalse())
}

func TestNegatedNamedSetRuleString(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("10.0.0.0/8")

	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(80))

	// NotSrcIPSet only → srcNet shows as !10.0.0.0/8
	rNegSrcIP := mustNew(WithAction(Accept), WithNotSrcIPSet(ipSet))
	Expect(rNegSrcIP.String()).To(Equal("Accept *{!10.0.0.0/8:*->*:*}"))

	// NotDstPortSet only → dstPort shows as !80
	rNotDstPort := mustNew(WithAction(Drop), WithNotDstPortSet(portSet))
	Expect(rNotDstPort.String()).To(Equal("Drop *{*:*->*:!80}"))
}

func TestIPPortSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	srcSet := set.NewIPPortSet()
	_ = srcSet.Add("10.0.0.0/8,1000-2000")
	dstSet := set.NewIPPortSet()
	_ = dstSet.Add("1.1.1.1,443")

	r := mustNew(WithSrcIPPortSet(srcSet), WithDstIPPortSet(dstSet))

	Expect(r.Match(packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(1500), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	))).To(BeTrue())

	Expect(r.Match(packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(999), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	))).To(BeFalse())
}

func TestNegatedIPPortSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	negSet := set.NewIPPortSet()
	_ = negSet.Add("10.0.0.0/8,53")

	r := mustNew(WithNotSrcIPPortSet(negSet), WithNotDstIPPortSet(negSet))

	// src port 53 and dst port 53 both in set → not matched
	Expect(r.Match(packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(53), packet.WithProto(proto.UDP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	))).To(BeFalse())

	// src 10.1.2.3:53 is excluded; any protocol is excluded now
	Expect(r.Match(packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(53), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	))).To(BeFalse())

	// src port not in set → src passes; dst also excluded → not matched
	Expect(r.Match(packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(80), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	))).To(BeFalse())

	// neither src nor dst in set → matched
	Expect(r.Match(packet.New(
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(80), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(80),
	))).To(BeTrue())
}

func TestIngressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := packet.New(packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := packet.New(packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktNoIface := packet.New(packet.WithSrcAddr("10.0.0.3"))

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

	pktEth0 := packet.New(packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := packet.New(packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktNoIface := packet.New(packet.WithSrcAddr("10.0.0.3"))

	// Rule excludes eth0
	r := mustNew(WithNotSrcIface("eth0"))
	Expect(r.Match(pktEth0)).To(BeFalse())
	Expect(r.Match(pktEth1)).To(BeTrue())
	Expect(r.Match(pktNoIface)).To(BeTrue())
}

func TestIngressIfaceAndNotIngressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := packet.New(packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := packet.New(packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktEth2 := packet.New(packet.WithSrcAddr("10.0.0.3"), packet.WithIngressIface("eth2"))

	// Allow eth0 and eth1, but not eth1 (net effect: only eth0)
	r := mustNew(WithSrcIface("eth0"), WithSrcIface("eth1"), WithNotSrcIface("eth1"))
	Expect(r.Match(pktEth0)).To(BeTrue())
	Expect(r.Match(pktEth1)).To(BeFalse())
	Expect(r.Match(pktEth2)).To(BeFalse())
}

func TestIngressIfaceRuleString(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(WithAction(Accept), WithSrcIface("eth0"))
	Expect(r.String()).To(Equal("Accept *{*:*->*:*} ingress_iface=eth0"))

	rNot := mustNew(WithAction(Drop), WithNotSrcIface("eth0"))
	Expect(rNot.String()).To(Equal("Drop *{*:*->*:*} ingress_iface=!eth0"))

	rBoth := mustNew(WithAction(Accept), WithSrcIface("eth0"), WithNotSrcIface("eth1"))
	Expect(rBoth.String()).To(Equal("Accept *{*:*->*:*} ingress_iface=eth0,!eth1"))

	rMultiNot := mustNew(WithAction(Accept), WithSrcIface("eth0"), WithSrcIface("eth1"), WithNotSrcIface("eth2"), WithNotSrcIface("eth3"))
	Expect(rMultiNot.String()).To(Equal("Accept *{*:*->*:*} ingress_iface={eth0,eth1},!{eth2,eth3}"))
}

func TestEgressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := packet.New(packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := packet.New(packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktNoIface := packet.New(packet.WithDstAddr("10.0.0.3"))

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

	pktEth0 := packet.New(packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := packet.New(packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktNoIface := packet.New(packet.WithDstAddr("10.0.0.3"))

	// Rule excludes eth0
	r := mustNew(WithNotDstIface("eth0"))
	Expect(r.Match(pktEth0)).To(BeFalse())
	Expect(r.Match(pktEth1)).To(BeTrue())
	Expect(r.Match(pktNoIface)).To(BeTrue())
}

func TestEgressIfaceAndNotEgressIfaceMatch(t *testing.T) {
	RegisterTestingT(t)

	pktEth0 := packet.New(packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := packet.New(packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktEth2 := packet.New(packet.WithDstAddr("10.0.0.3"), packet.WithEgressIface("eth2"))

	// Allow eth0 and eth1, but not eth1 (net effect: only eth0)
	r := mustNew(WithDstIface("eth0"), WithDstIface("eth1"), WithNotDstIface("eth1"))
	Expect(r.Match(pktEth0)).To(BeTrue())
	Expect(r.Match(pktEth1)).To(BeFalse())
	Expect(r.Match(pktEth2)).To(BeFalse())
}

func TestEgressIfaceRuleString(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(WithAction(Accept), WithDstIface("eth0"))
	Expect(r.String()).To(Equal("Accept *{*:*->*:*} egress_iface=eth0"))

	rNot := mustNew(WithAction(Drop), WithNotDstIface("eth0"))
	Expect(rNot.String()).To(Equal("Drop *{*:*->*:*} egress_iface=!eth0"))

	rBoth := mustNew(WithAction(Accept), WithDstIface("eth0"), WithNotDstIface("eth1"))
	Expect(rBoth.String()).To(Equal("Accept *{*:*->*:*} egress_iface=eth0,!eth1"))

	rMultiNot := mustNew(WithAction(Accept), WithDstIface("eth0"), WithDstIface("eth1"), WithNotDstIface("eth2"), WithNotDstIface("eth3"))
	Expect(rMultiNot.String()).To(Equal("Accept *{*:*->*:*} egress_iface={eth0,eth1},!{eth2,eth3}"))
}

func TestBothIngressAndEgressIfaceRuleString(t *testing.T) {
	RegisterTestingT(t)

	r := mustNew(WithAction(Accept), WithSrcIface("eth0"), WithDstIface("eth1"))
	Expect(r.String()).To(Equal("Accept *{*:*->*:*} ingress_iface=eth0 egress_iface=eth1"))
}

func TestIfaceSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	ifaceSet := set.NewIfaceSet()
	_ = ifaceSet.Add("eth0")
	_ = ifaceSet.Add("eth1")

	pktIngressEth0 := packet.New(packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktIngressEth1 := packet.New(packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktIngressEth2 := packet.New(packet.WithSrcAddr("10.0.0.3"), packet.WithIngressIface("eth2"))
	pktNoIface := packet.New(packet.WithSrcAddr("10.0.0.4"))

	// IfaceSet on Source — matches against ingress iface.
	rSrc := mustNew(WithSrcIfaceSet(ifaceSet))
	Expect(rSrc.Match(pktIngressEth0)).To(BeTrue())
	Expect(rSrc.Match(pktIngressEth1)).To(BeTrue())
	Expect(rSrc.Match(pktIngressEth2)).To(BeFalse())
	Expect(rSrc.Match(pktNoIface)).To(BeFalse())

	pktEgressEth0 := packet.New(packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEgressEth1 := packet.New(packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktEgressEth2 := packet.New(packet.WithDstAddr("10.0.0.3"), packet.WithEgressIface("eth2"))

	// IfaceSet on Destination — matches against egress iface.
	rDst := mustNew(WithDstIfaceSet(ifaceSet))
	Expect(rDst.Match(pktEgressEth0)).To(BeTrue())
	Expect(rDst.Match(pktEgressEth1)).To(BeTrue())
	Expect(rDst.Match(pktEgressEth2)).To(BeFalse())
}

func TestNotIfaceSetRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	ifaceSet := set.NewIfaceSet()
	_ = ifaceSet.Add("eth0")

	pktIngressEth0 := packet.New(packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktIngressEth1 := packet.New(packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))

	// NotSrcIfaceSet: packets on ingress eth0 should NOT match.
	rNotSrc := mustNew(WithNotSrcIfaceSet(ifaceSet))
	Expect(rNotSrc.Match(pktIngressEth0)).To(BeFalse())
	Expect(rNotSrc.Match(pktIngressEth1)).To(BeTrue())

	pktEgressEth0 := packet.New(packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEgressEth1 := packet.New(packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))

	// NotDstIfaceSet: packets on egress eth0 should NOT match.
	rNotDst := mustNew(WithNotDstIfaceSet(ifaceSet))
	Expect(rNotDst.Match(pktEgressEth0)).To(BeFalse())
	Expect(rNotDst.Match(pktEgressEth1)).To(BeTrue())
}

func TestIfaceSetRuleString(t *testing.T) {
	RegisterTestingT(t)

	ifaceSet := set.NewIfaceSet()
	_ = ifaceSet.Add("eth0")

	rSrc := mustNew(WithAction(Accept), WithSrcIfaceSet(ifaceSet))
	Expect(rSrc.String()).To(Equal("Accept *{*:*->*:*} ingress_iface=eth0"))

	notIfaceSet := set.NewIfaceSet()
	_ = notIfaceSet.Add("eth1")

	rNotSrc := mustNew(WithAction(Drop), WithNotSrcIfaceSet(notIfaceSet))
	Expect(rNotSrc.String()).To(Equal("Drop *{*:*->*:*} ingress_iface=!eth1"))

	// Egress (dst) iface set string representation.
	rDst := mustNew(WithAction(Accept), WithDstIfaceSet(ifaceSet))
	Expect(rDst.String()).To(Equal("Accept *{*:*->*:*} egress_iface=eth0"))

	rNotDst := mustNew(WithAction(Drop), WithNotDstIfaceSet(notIfaceSet))
	Expect(rNotDst.String()).To(Equal("Drop *{*:*->*:*} egress_iface=!eth1"))

	// Combined ingress + egress iface sets.
	rBoth := mustNew(WithAction(Accept), WithSrcIfaceSet(ifaceSet), WithDstIfaceSet(notIfaceSet))
	Expect(rBoth.String()).To(Equal("Accept *{*:*->*:*} ingress_iface=eth0 egress_iface=eth1"))
}
