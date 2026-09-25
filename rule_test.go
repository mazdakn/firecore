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
)

func mustNew(opts ...RuleOption) *Rule {
	r, err := NewRule(opts...)
	if err != nil {
		panic(fmt.Sprintf("NewRule: %v", err))
	}
	return r
}

func mustNewPacket(t testing.TB, opts ...packet.Option) *packet.Packet {
	t.Helper()
	pkt, err := packet.New(opts...)
	if err != nil {
		t.Fatalf("packet.New: %v", err)
	}
	return pkt
}

func TestWithNameEmptyFails(t *testing.T) {
	r, err := NewRule(WithName(""))
	if err == nil {
		t.Fatal("NewRule(WithName(\"\")) expected error, got nil")
	}
	if r != nil {
		t.Errorf("NewRule(WithName(\"\")) expected nil rule, got %v", r)
	}
}

func TestNewRuleNilOptionFails(t *testing.T) {
	r, err := NewRule(WithAction(Accept), nil)
	if err == nil {
		t.Fatal("NewRule with nil option expected error, got nil")
	}
	if r != nil {
		t.Errorf("NewRule with nil option expected nil rule, got %v", r)
	}
}

func TestRuleMatchNilPacketReturnsFalse(t *testing.T) {
	r := mustNew(WithProto(proto.TCP), WithDstPort(80), WithAction(Accept))
	if r.Match(nil) {
		t.Error("r.Match(nil) = true; want false")
	}
	if r.MatchWithConntrackState(nil, conntrack.StateEstablished) {
		t.Error("r.MatchWithConntrackState(nil, established) = true; want false")
	}

	// A nil packet must not satisfy a negated-only condition either
	// (fail closed, not fail open).
	rNegated := mustNew(WithNotProto(proto.TCP))
	if rNegated.Match(nil) {
		t.Error("rNegated.Match(nil) = true; want false")
	}
}

func TestEmptyRule(t *testing.T) {
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
			if !rule.Match(pkt) {
				t.Errorf("rule.Match(%s) = false; want true", pkt)
			}
		})
	}
}

func TestRuleIPFamilyMismatch(t *testing.T) {
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
			if r.Match(pktV6) {
				t.Errorf("IPv4 rule %d matched IPv6 packet", i)
			}
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
			if r.Match(pktV4) {
				t.Errorf("IPv6 rule %d matched IPv4 packet", i)
			}
		})
	}
}

func TestRuleMatch(t *testing.T) {
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
			if !r.Match(pktShouldMatch) {
				t.Errorf("rule %d should match, but returned false", i)
			}
		})
		t.Run(fmt.Sprintf("rule %d should not match", i), func(t *testing.T) {
			if r.Match(pktShouldNotMatch) {
				t.Errorf("rule %d should not match, but returned true", i)
			}
		})
	}
}

func TestRuleMatchV6(t *testing.T) {
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
			if !r.Match(pktShouldMatch) {
				t.Errorf("rule %d should match, but returned false", i)
			}
		})
		t.Run(fmt.Sprintf("rule %d should not match", i), func(t *testing.T) {
			if r.Match(pktShouldNotMatch) {
				t.Errorf("rule %d should not match, but returned true", i)
			}
		})
	}
}

func TestRuleConntrackStateMatch(t *testing.T) {
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

	if !r.MatchWithConntrackState(pkt, conntrack.StateEstablished) {
		t.Error("r.MatchWithConntrackState(pkt, established) = false; want true")
	}
	if r.MatchWithConntrackState(pkt, conntrack.StateNew) {
		t.Error("r.MatchWithConntrackState(pkt, new) = true; want false")
	}
}

func TestWithConnStateInvalidFails(t *testing.T) {
	r, err := NewRule(WithConnState(conntrack.State("bogus")))
	if err == nil {
		t.Fatal("NewRule(WithConnState(bogus)) expected error, got nil")
	}
	if r != nil {
		t.Errorf("expected nil rule, got %v", r)
	}
}

func TestWithNotConnStateInvalidFails(t *testing.T) {
	r, err := NewRule(WithNotConnState(conntrack.State("bogus")))
	if err == nil {
		t.Fatal("NewRule(WithNotConnState(bogus)) expected error, got nil")
	}
	if r != nil {
		t.Errorf("expected nil rule, got %v", r)
	}
}

func TestRuleNegatedConntrackStateMatch(t *testing.T) {
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

	if !r.MatchWithConntrackState(pkt, conntrack.StateNew) {
		t.Error("r.MatchWithConntrackState(pkt, new) = false; want true")
	}
	if r.MatchWithConntrackState(pkt, conntrack.StateEstablished) {
		t.Error("r.MatchWithConntrackState(pkt, established) = true; want false")
	}
}

func TestRulePayloadMatch(t *testing.T) {
	r := mustNew(WithPayload(`GET /admin`))

	pktMatch := mustNewPacket(t, packet.WithPayload([]byte("GET /admin HTTP/1.1")))
	pktNoMatch := mustNewPacket(t, packet.WithPayload([]byte("GET /public HTTP/1.1")))

	if !r.Match(pktMatch) {
		t.Error("r.Match(pktMatch) = false; want true")
	}
	if r.Match(pktNoMatch) {
		t.Error("r.Match(pktNoMatch) = true; want false")
	}
}

func TestNewReturnsErrorOnInvalidPayloadPattern(t *testing.T) {
	_, err := NewRule(WithPayload(`[`))
	if err == nil {
		t.Fatal("NewRule(WithPayload([)) expected error, got nil")
	}
}

func TestActionString(t *testing.T) {
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
			if got := tt.action.String(); got != tt.expected {
				t.Errorf("action.String() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestActionValidate(t *testing.T) {
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
				if err == nil {
					t.Errorf("action.Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("action.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNewReturnsErrorOnInvalidCIDR(t *testing.T) {
	tests := []string{
		"invalid-cidr",
		"256.256.256.256/32", // Invalid IP
		"not-an-ip/24",
	}

	for _, cidr := range tests {
		t.Run(fmt.Sprintf("should error on %s (src)", cidr), func(t *testing.T) {
			_, err := NewRule(WithSrcNet(cidr))
			if err == nil {
				t.Errorf("NewRule(WithSrcNet(%q)) expected error, got nil", cidr)
			}
		})
		t.Run(fmt.Sprintf("should error on %s (dst)", cidr), func(t *testing.T) {
			_, err := NewRule(WithDstNet(cidr))
			if err == nil {
				t.Errorf("NewRule(WithDstNet(%q)) expected error, got nil", cidr)
			}
		})
	}
}

func TestNewRuleSupportsSingleIPAddress(t *testing.T) {
	r, err := NewRule(WithSrcNet("10.10.10.1"), WithAction(Accept))
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	pktMatch := mustNewPacket(t, packet.WithSrcAddr("10.10.10.1"))
	pktNoMatch := mustNewPacket(t, packet.WithSrcAddr("10.10.10.2"))

	if !r.Match(pktMatch) {
		t.Error("r.Match(pktMatch) = false; want true")
	}
	if r.Match(pktNoMatch) {
		t.Error("r.Match(pktNoMatch) = true; want false")
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
				if err == nil {
					t.Errorf("ParseAction(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseAction(%q) unexpected error: %v", tt.input, err)
				}
				if action != tt.expected {
					t.Errorf("ParseAction(%q) = %v; want %v", tt.input, action, tt.expected)
				}
			}
		})
	}
}

func TestRulePacketCounter(t *testing.T) {
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
	if got := rule.PacketCount(); got != 0 {
		t.Errorf("rule.PacketCount() = %d; want 0", got)
	}

	// Match a packet, count should increment to 1
	if !rule.Match(pktMatch) {
		t.Error("expected match")
	}
	if got := rule.PacketCount(); got != 1 {
		t.Errorf("rule.PacketCount() = %d; want 1", got)
	}

	// Match another packet, count should increment to 2
	if !rule.Match(pktMatch) {
		t.Error("expected match")
	}
	if got := rule.PacketCount(); got != 2 {
		t.Errorf("rule.PacketCount() = %d; want 2", got)
	}

	// Non-matching packet should not increment counter
	if rule.Match(pktNoMatch) {
		t.Error("expected no match")
	}
	if got := rule.PacketCount(); got != 2 {
		t.Errorf("rule.PacketCount() = %d; want 2", got)
	}

	// Reset counter
	rule.ResetPacketCount()
	if got := rule.PacketCount(); got != 0 {
		t.Errorf("rule.PacketCount() = %d; want 0", got)
	}

	// Match after reset should increment from 0
	if !rule.Match(pktMatch) {
		t.Error("expected match")
	}
	if got := rule.PacketCount(); got != 1 {
		t.Errorf("rule.PacketCount() = %d; want 1", got)
	}
}

func TestRulePacketCounterConcurrency(t *testing.T) {
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
	if got := rule.PacketCount(); got != expectedCount {
		t.Errorf("rule.PacketCount() = %d; want %d", got, expectedCount)
	}
}

func TestRuleByteCounter(t *testing.T) {
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
	if got := rule.ByteCount(); got != 0 {
		t.Errorf("rule.ByteCount() = %d; want 0", got)
	}

	// Match a packet, byte count should increase by its full size, not its
	// (shorter, or possibly absent) payload length
	if !rule.Match(pktMatch) {
		t.Error("expected match")
	}
	if got := rule.ByteCount(); got != 74 {
		t.Errorf("rule.ByteCount() = %d; want 74", got)
	}

	// Match another packet, byte count should accumulate
	if !rule.Match(pktMatch) {
		t.Error("expected match")
	}
	if got := rule.ByteCount(); got != 148 {
		t.Errorf("rule.ByteCount() = %d; want 148", got)
	}

	// Non-matching packet should not add to the byte count
	if rule.Match(pktNoMatch) {
		t.Error("expected no match")
	}
	if got := rule.ByteCount(); got != 148 {
		t.Errorf("rule.ByteCount() = %d; want 148", got)
	}

	// Reset counter
	rule.ResetByteCount()
	if got := rule.ByteCount(); got != 0 {
		t.Errorf("rule.ByteCount() = %d; want 0", got)
	}

	// Match after reset should accumulate from 0
	if !rule.Match(pktMatch) {
		t.Error("expected match")
	}
	if got := rule.ByteCount(); got != 74 {
		t.Errorf("rule.ByteCount() = %d; want 74", got)
	}
}

func TestRuleWithName(t *testing.T) {
	// Rule without name has an empty Name
	ruleNoName := mustNew(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80))
	if ruleNoName.Name != "" {
		t.Errorf("ruleNoName.Name = %q; want empty string", ruleNoName.Name)
	}

	// Rule with name should keep it
	ruleWithName := mustNew(WithAction(Accept), WithProto(proto.TCP), WithDstPort(80), WithName("allow-http"))
	if ruleWithName.Name != "allow-http" {
		t.Errorf("ruleWithName.Name = %q; want allow-http", ruleWithName.Name)
	}

	// Setting Name directly should also work
	ruleDirectName := mustNew(WithAction(Drop))
	ruleDirectName.Name = "block-all"
	if ruleDirectName.Name != "block-all" {
		t.Errorf("ruleDirectName.Name = %q; want block-all", ruleDirectName.Name)
	}
}

func TestNegatedRuleMatch(t *testing.T) {
	// Packet that will be matched against negated rules
	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.10.10.1"), packet.WithSrcPort(55555), packet.WithProto(proto.UDP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(53),
	)

	// Negated protocol: should NOT match proto 17, but SHOULD match everything else
	ruleNotProto := mustNew(WithNotProto(proto.UDP))
	if ruleNotProto.Match(pkt) {
		t.Error("ruleNotProto.Match(pkt) = true; want false")
	}

	ruleNotProtoOther := mustNew(WithNotProto(proto.TCP))
	if !ruleNotProtoOther.Match(pkt) {
		t.Error("ruleNotProtoOther.Match(pkt) = false; want true")
	}

	// Negated source port: should NOT match src port 55555
	ruleNotSrcPort := mustNew(WithNotSrcPort(55555))
	if ruleNotSrcPort.Match(pkt) {
		t.Error("ruleNotSrcPort.Match(pkt) = true; want false")
	}

	ruleNotSrcPortOther := mustNew(WithNotSrcPort(12345))
	if !ruleNotSrcPortOther.Match(pkt) {
		t.Error("ruleNotSrcPortOther.Match(pkt) = false; want true")
	}

	// Negated destination port: should NOT match dst port 53
	ruleNotDstPort := mustNew(WithNotDstPort(53))
	if ruleNotDstPort.Match(pkt) {
		t.Error("ruleNotDstPort.Match(pkt) = true; want false")
	}

	ruleNotDstPortOther := mustNew(WithNotDstPort(80))
	if !ruleNotDstPortOther.Match(pkt) {
		t.Error("ruleNotDstPortOther.Match(pkt) = false; want true")
	}

	// Negated source network: should NOT match 10.10.10.0/24
	ruleNotSrcNet := mustNew(WithNotSrcNet("10.10.10.0/24"))
	if ruleNotSrcNet.Match(pkt) {
		t.Error("ruleNotSrcNet.Match(pkt) = true; want false")
	}

	ruleNotSrcNetOther := mustNew(WithNotSrcNet("192.168.0.0/16"))
	if !ruleNotSrcNetOther.Match(pkt) {
		t.Error("ruleNotSrcNetOther.Match(pkt) = false; want true")
	}

	// Negated destination network: should NOT match 1.1.1.1/32
	ruleNotDstNet := mustNew(WithNotDstNet("1.1.1.1/32"))
	if ruleNotDstNet.Match(pkt) {
		t.Error("ruleNotDstNet.Match(pkt) = true; want false")
	}

	ruleNotDstNetOther := mustNew(WithNotDstNet("2.2.2.2/32"))
	if !ruleNotDstNetOther.Match(pkt) {
		t.Error("ruleNotDstNetOther.Match(pkt) = false; want true")
	}
}

func TestNegatedRuleConfig(t *testing.T) {
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
	if _, ok := findMatcher[*matcher.ProtoMatcher](rule, true); !ok {
		t.Error("expected negated ProtoMatcher")
	}
	if _, ok := findSrcSet(rule, true, set.TypePort); !ok {
		t.Error("expected negated SrcSet Port")
	}
	if _, ok := findDstSet(rule, true, set.TypePort); !ok {
		t.Error("expected negated DstSet Port")
	}
	if _, ok := findSrcSet(rule, true, set.TypeIP); !ok {
		t.Error("expected negated SrcSet IP")
	}
	if _, ok := findDstSet(rule, true, set.TypeIP); !ok {
		t.Error("expected negated DstSet IP")
	}
	// Positive (non-negated) matchers should be absent when only negated
	// values are specified.
	if _, ok := findMatcher[*matcher.ProtoMatcher](rule, false); ok {
		t.Error("expected no positive ProtoMatcher")
	}
	if _, ok := findSrcSet(rule, false, set.TypePort); ok {
		t.Error("expected no positive SrcSet Port")
	}
	if _, ok := findDstSet(rule, false, set.TypePort); ok {
		t.Error("expected no positive DstSet Port")
	}
	if _, ok := findSrcSet(rule, false, set.TypeIP); ok {
		t.Error("expected no positive SrcSet IP")
	}
	if _, ok := findDstSet(rule, false, set.TypeIP); ok {
		t.Error("expected no positive DstSet IP")
	}

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
	if _, ok := findMatcher[*matcher.ProtoMatcher](ruleCombined, false); !ok {
		t.Error("expected positive ProtoMatcher")
	}
	if _, ok := findMatcher[*matcher.ProtoMatcher](ruleCombined, true); !ok {
		t.Error("expected negated ProtoMatcher")
	}
	if _, ok := findSrcSet(ruleCombined, false, set.TypePort); !ok {
		t.Error("expected positive SrcSet Port")
	}
	if _, ok := findSrcSet(ruleCombined, true, set.TypePort); !ok {
		t.Error("expected negated SrcSet Port")
	}
	if _, ok := findDstSet(ruleCombined, false, set.TypePort); !ok {
		t.Error("expected positive DstSet Port")
	}
	if _, ok := findDstSet(ruleCombined, true, set.TypePort); !ok {
		t.Error("expected negated DstSet Port")
	}
	if _, ok := findSrcSet(ruleCombined, false, set.TypeIP); !ok {
		t.Error("expected positive SrcSet IP")
	}
	if _, ok := findSrcSet(ruleCombined, true, set.TypeIP); !ok {
		t.Error("expected negated SrcSet IP")
	}
	if _, ok := findDstSet(ruleCombined, false, set.TypeIP); !ok {
		t.Error("expected positive DstSet IP")
	}
	if _, ok := findDstSet(ruleCombined, true, set.TypeIP); !ok {
		t.Error("expected negated DstSet IP")
	}
}

func TestCombinedPositiveAndNegativeRuleMatch(t *testing.T) {
	// Rule matches src in 10.0.0.0/8 but NOT in 10.10.0.0/16
	rule := mustNew(WithSrcNet("10.0.0.0/8"), WithNotSrcNet("10.10.0.0/16"))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	pktMatch := mustNewPacket(t, packet.WithSrcAddr("10.1.2.3"))
	if !rule.Match(pktMatch) {
		t.Error("rule.Match(pktMatch) = false; want true")
	}

	// In 10.0.0.0/8 AND in 10.10.0.0/16 → should not match (excluded by neg)
	pktNotHit := mustNewPacket(t, packet.WithSrcAddr("10.10.0.5"))
	if rule.Match(pktNotHit) {
		t.Error("rule.Match(pktNotHit) = true; want false")
	}

	// Not in 10.0.0.0/8 at all → should not match (excluded by positive)
	pktOutside := mustNewPacket(t, packet.WithSrcAddr("172.16.0.1"))
	if rule.Match(pktOutside) {
		t.Error("rule.Match(pktOutside) = true; want false")
	}

	// Rule matches proto 17 AND NOT proto 6 (proto 6 is excluded, proto 17 is required)
	ruleProto := mustNew(WithProto(proto.UDP), WithNotProto(proto.TCP))
	pktProto17 := mustNewPacket(t, packet.WithProto(proto.UDP))
	pktProto6 := mustNewPacket(t, packet.WithProto(proto.TCP))
	pktProto1 := mustNewPacket(t, packet.WithProto(proto.ICMP))
	if !ruleProto.Match(pktProto17) {
		t.Error("ruleProto.Match(pktProto17) = false; want true")
	}
	if ruleProto.Match(pktProto6) {
		t.Error("ruleProto.Match(pktProto6) = true; want false")
	}
	if ruleProto.Match(pktProto1) {
		t.Error("ruleProto.Match(pktProto1) = true; want false")
	}
}

func TestWithSetNilFails(t *testing.T) {
	r, err := NewRule(WithSrcSet(nil))
	if err == nil {
		t.Fatal("NewRule(WithSrcSet(nil)) expected error, got nil")
	}
	if r != nil {
		t.Errorf("expected nil rule, got %v", r)
	}

	r, err = NewRule(WithNotSrcSet(nil))
	if err == nil {
		t.Fatal("NewRule(WithNotSrcSet(nil)) expected error, got nil")
	}
	if r != nil {
		t.Errorf("expected nil rule, got %v", r)
	}

	r, err = NewRule(WithDstSet(nil))
	if err == nil {
		t.Fatal("NewRule(WithDstSet(nil)) expected error, got nil")
	}
	if r != nil {
		t.Errorf("expected nil rule, got %v", r)
	}

	r, err = NewRule(WithNotDstSet(nil))
	if err == nil {
		t.Fatal("NewRule(WithNotDstSet(nil)) expected error, got nil")
	}
	if r != nil {
		t.Errorf("expected nil rule, got %v", r)
	}
}

func TestNamedSetRuleMatchWithNamedPortString(t *testing.T) {
	// Build a port set using well-known port names as strings.
	portSet := set.NewPortSet()
	_ = portSet.Add("http")
	_ = portSet.Add("https")

	pktHTTP := mustNewPacket(t, packet.WithDstPort(80))
	pktHTTPS := mustNewPacket(t, packet.WithDstPort(443))
	pktOther := mustNewPacket(t, packet.WithDstPort(8080))

	r := mustNew(WithDstSet(portSet))
	if !r.Match(pktHTTP) {
		t.Error("r.Match(pktHTTP) = false; want true")
	}
	if !r.Match(pktHTTPS) {
		t.Error("r.Match(pktHTTPS) = false; want true")
	}
	if r.Match(pktOther) {
		t.Error("r.Match(pktOther) = true; want false")
	}
}

func TestNamedSetRuleMatch(t *testing.T) {
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
	if !r.Match(pktMatch) {
		t.Error("r.Match(pktMatch) = false; want true")
	}
	if r.Match(pktNoMatchIP) {
		t.Error("r.Match(pktNoMatchIP) = true; want false")
	}
	if r.Match(pktNoMatchPort) {
		t.Error("r.Match(pktNoMatchPort) = true; want false")
	}
}

func TestNamedSetRuleMatchDstIPSet(t *testing.T) {
	ipSet := set.NewIPSet()
	_ = ipSet.Add("1.1.1.0/24")

	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("1.1.1.1"),
	)
	pktNoMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithDstAddr("2.2.2.2"),
	)

	r := mustNew(WithDstSet(ipSet))
	if !r.Match(pktMatch) {
		t.Error("r.Match(pktMatch) = false; want true")
	}
	if r.Match(pktNoMatch) {
		t.Error("r.Match(pktNoMatch) = true; want false")
	}
}

func TestNamedSetRuleMatchSrcPortSet(t *testing.T) {
	portSet := set.NewPortSet()
	_ = portSet.Add(uint16(55555))

	pktMatch := mustNewPacket(t,
		packet.WithSrcPort(55555),
	)
	pktNoMatch := mustNewPacket(t,
		packet.WithSrcPort(12345),
	)

	r := mustNew(WithSrcSet(portSet))
	if !r.Match(pktMatch) {
		t.Error("r.Match(pktMatch) = false; want true")
	}
	if r.Match(pktNoMatch) {
		t.Error("r.Match(pktNoMatch) = true; want false")
	}
}

func TestNegatedNamedSetRuleMatch(t *testing.T) {
	// NotSrcIPSet: packets whose source is in the set should NOT match.
	srcIPSet := set.NewIPSet()
	_ = srcIPSet.Add("10.0.0.0/8")

	rNegSrc := mustNew(WithNotSrcSet(srcIPSet))
	pktInSet := mustNewPacket(t, packet.WithSrcAddr("10.1.2.3"))
	pktOutSet := mustNewPacket(t, packet.WithSrcAddr("192.168.1.1"))
	if rNegSrc.Match(pktInSet) {
		t.Error("rNegSrc.Match(pktInSet) = true; want false")
	}
	if !rNegSrc.Match(pktOutSet) {
		t.Error("rNegSrc.Match(pktOutSet) = false; want true")
	}

	// NotDstIPSet: packets whose destination is in the set should NOT match.
	dstIPSet := set.NewIPSet()
	_ = dstIPSet.Add("1.1.1.0/24")

	rNegDst := mustNew(WithNotDstSet(dstIPSet))
	pktDstIn := mustNewPacket(t, packet.WithDstAddr("1.1.1.1"))
	pktDstOut := mustNewPacket(t, packet.WithDstAddr("2.2.2.2"))
	if rNegDst.Match(pktDstIn) {
		t.Error("rNegDst.Match(pktDstIn) = true; want false")
	}
	if !rNegDst.Match(pktDstOut) {
		t.Error("rNegDst.Match(pktDstOut) = false; want true")
	}

	// NotSrcPortSet: packets whose source port is in the set should NOT match.
	srcPortSet := set.NewPortSet()
	_ = srcPortSet.Add(uint16(55555))

	rNotSrcPort := mustNew(WithNotSrcSet(srcPortSet))
	pktSrcPortIn := mustNewPacket(t, packet.WithSrcPort(55555))
	pktSrcPortOut := mustNewPacket(t, packet.WithSrcPort(12345))
	if rNotSrcPort.Match(pktSrcPortIn) {
		t.Error("rNotSrcPort.Match(pktSrcPortIn) = true; want false")
	}
	if !rNotSrcPort.Match(pktSrcPortOut) {
		t.Error("rNotSrcPort.Match(pktSrcPortOut) = false; want true")
	}

	// NotDstPortSet: packets whose destination port is in the set should NOT match.
	dstPortSet := set.NewPortSet()
	_ = dstPortSet.Add(uint16(80))

	rNotDstPort := mustNew(WithNotDstSet(dstPortSet))
	pktDstPortIn := mustNewPacket(t, packet.WithDstPort(80))
	pktDstPortOut := mustNewPacket(t, packet.WithDstPort(443))
	if rNotDstPort.Match(pktDstPortIn) {
		t.Error("rNotDstPort.Match(pktDstPortIn) = true; want false")
	}
	if !rNotDstPort.Match(pktDstPortOut) {
		t.Error("rNotDstPort.Match(pktDstPortOut) = false; want true")
	}
}

func TestCombinedPositiveAndNegativeNamedSetMatch(t *testing.T) {
	// Match src in 10.0.0.0/8 named set but NOT in 10.10.0.0/16 named set.
	posSet := set.NewIPSet()
	_ = posSet.Add("10.0.0.0/8")

	negSet := set.NewIPSet()
	_ = negSet.Add("10.10.0.0/16")

	r := mustNew(WithSrcSet(posSet), WithNotSrcSet(negSet))

	// In 10.0.0.0/8, not in 10.10.0.0/16 → should match
	pktMatch := mustNewPacket(t, packet.WithSrcAddr("10.1.2.3"))
	if !r.Match(pktMatch) {
		t.Error("r.Match(pktMatch) = false; want true")
	}
	// In 10.0.0.0/8 AND in 10.10.0.0/16 → excluded by neg
	pktNotHit := mustNewPacket(t, packet.WithSrcAddr("10.10.0.5"))
	if r.Match(pktNotHit) {
		t.Error("r.Match(pktNotHit) = true; want false")
	}
	// Not in 10.0.0.0/8 at all → excluded by positive
	pktOutside := mustNewPacket(t, packet.WithSrcAddr("172.16.0.1"))
	if r.Match(pktOutside) {
		t.Error("r.Match(pktOutside) = true; want false")
	}
}

func TestIPPortSetRuleMatch(t *testing.T) {
	srcSet := set.NewIPPortSet()
	_ = srcSet.Add("10.0.0.0/8,1000-2000")
	dstSet := set.NewIPPortSet()
	_ = dstSet.Add("1.1.1.1,443")

	r := mustNew(WithSrcSet(srcSet), WithDstSet(dstSet))

	pktMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(1500), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	)
	if !r.Match(pktMatch) {
		t.Error("r.Match(pktMatch) = false; want true")
	}

	pktNoMatch := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(999), packet.WithProto(proto.TCP),
		packet.WithDstAddr("1.1.1.1"), packet.WithDstPort(443),
	)
	if r.Match(pktNoMatch) {
		t.Error("r.Match(pktNoMatch) = true; want false")
	}
}

func TestNegatedIPPortSetRuleMatch(t *testing.T) {
	negSet := set.NewIPPortSet()
	_ = negSet.Add("10.0.0.0/8,53")

	r := mustNew(WithNotSrcSet(negSet), WithNotDstSet(negSet))

	// src port 53 and dst port 53 both in set → not matched
	pkt1 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(53), packet.WithProto(proto.UDP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	)
	if r.Match(pkt1) {
		t.Error("r.Match(pkt1) = true; want false")
	}

	// src 10.1.2.3:53 is excluded; any protocol is excluded now
	pkt2 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(53), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	)
	if r.Match(pkt2) {
		t.Error("r.Match(pkt2) = true; want false")
	}

	// src port not in set → src passes; dst also excluded → not matched
	pkt3 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(80), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(53),
	)
	if r.Match(pkt3) {
		t.Error("r.Match(pkt3) = true; want false")
	}

	// neither src nor dst in set → matched
	pkt4 := mustNewPacket(t,
		packet.WithSrcAddr("10.1.2.3"), packet.WithSrcPort(80), packet.WithProto(proto.TCP),
		packet.WithDstAddr("10.2.3.4"), packet.WithDstPort(80),
	)
	if !r.Match(pkt4) {
		t.Error("r.Match(pkt4) = false; want true")
	}
}

func TestIngressIfaceMatch(t *testing.T) {
	pktEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"))

	// Rule matches only eth0
	r := mustNew(WithSrcIface("eth0"))
	if !r.Match(pktEth0) {
		t.Error("r.Match(pktEth0) = false; want true")
	}
	if r.Match(pktEth1) {
		t.Error("r.Match(pktEth1) = true; want false")
	}
	if r.Match(pktNoIface) {
		t.Error("r.Match(pktNoIface) = true; want false")
	}

	// Rule matches eth0 or eth1
	rMulti := mustNew(WithSrcIface("eth0"), WithSrcIface("eth1"))
	if !rMulti.Match(pktEth0) {
		t.Error("rMulti.Match(pktEth0) = false; want true")
	}
	if !rMulti.Match(pktEth1) {
		t.Error("rMulti.Match(pktEth1) = false; want true")
	}
	if rMulti.Match(pktNoIface) {
		t.Error("rMulti.Match(pktNoIface) = true; want false")
	}

	// Rule with no interface constraint matches all
	rAny := mustNew()
	if !rAny.Match(pktEth0) {
		t.Error("rAny.Match(pktEth0) = false; want true")
	}
	if !rAny.Match(pktNoIface) {
		t.Error("rAny.Match(pktNoIface) = false; want true")
	}
}

func TestNotIngressIfaceMatch(t *testing.T) {
	pktEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"))

	// Rule excludes eth0
	r := mustNew(WithNotSrcIface("eth0"))
	if r.Match(pktEth0) {
		t.Error("r.Match(pktEth0) = true; want false")
	}
	if !r.Match(pktEth1) {
		t.Error("r.Match(pktEth1) = false; want true")
	}
	if !r.Match(pktNoIface) {
		t.Error("r.Match(pktNoIface) = false; want true")
	}
}

func TestIngressIfaceAndNotIngressIfaceMatch(t *testing.T) {
	pktEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktEth2 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"), packet.WithIngressIface("eth2"))

	// Allow eth0 and eth1, but not eth1 (net effect: only eth0)
	r := mustNew(WithSrcIface("eth0"), WithSrcIface("eth1"), WithNotSrcIface("eth1"))
	if !r.Match(pktEth0) {
		t.Error("r.Match(pktEth0) = false; want true")
	}
	if r.Match(pktEth1) {
		t.Error("r.Match(pktEth1) = true; want false")
	}
	if r.Match(pktEth2) {
		t.Error("r.Match(pktEth2) = true; want false")
	}
}

func TestEgressIfaceMatch(t *testing.T) {
	pktEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"))

	// Rule matches only eth0
	r := mustNew(WithDstIface("eth0"))
	if !r.Match(pktEth0) {
		t.Error("r.Match(pktEth0) = false; want true")
	}
	if r.Match(pktEth1) {
		t.Error("r.Match(pktEth1) = true; want false")
	}
	if r.Match(pktNoIface) {
		t.Error("r.Match(pktNoIface) = true; want false")
	}

	// Rule matches eth0 or eth1
	rMulti := mustNew(WithDstIface("eth0"), WithDstIface("eth1"))
	if !rMulti.Match(pktEth0) {
		t.Error("rMulti.Match(pktEth0) = false; want true")
	}
	if !rMulti.Match(pktEth1) {
		t.Error("rMulti.Match(pktEth1) = false; want true")
	}
	if rMulti.Match(pktNoIface) {
		t.Error("rMulti.Match(pktNoIface) = true; want false")
	}

	// Rule with no interface constraint matches all
	rAny := mustNew()
	if !rAny.Match(pktEth0) {
		t.Error("rAny.Match(pktEth0) = false; want true")
	}
	if !rAny.Match(pktNoIface) {
		t.Error("rAny.Match(pktNoIface) = false; want true")
	}
}

func TestNotEgressIfaceMatch(t *testing.T) {
	pktEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktNoIface := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"))

	// Rule excludes eth0
	r := mustNew(WithNotDstIface("eth0"))
	if r.Match(pktEth0) {
		t.Error("r.Match(pktEth0) = true; want false")
	}
	if !r.Match(pktEth1) {
		t.Error("r.Match(pktEth1) = false; want true")
	}
	if !r.Match(pktNoIface) {
		t.Error("r.Match(pktNoIface) = false; want true")
	}
}

func TestEgressIfaceAndNotEgressIfaceMatch(t *testing.T) {
	pktEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktEth2 := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"), packet.WithEgressIface("eth2"))

	// Allow eth0 and eth1, but not eth1 (net effect: only eth0)
	r := mustNew(WithDstIface("eth0"), WithDstIface("eth1"), WithNotDstIface("eth1"))
	if !r.Match(pktEth0) {
		t.Error("r.Match(pktEth0) = false; want true")
	}
	if r.Match(pktEth1) {
		t.Error("r.Match(pktEth1) = true; want false")
	}
	if r.Match(pktEth2) {
		t.Error("r.Match(pktEth2) = true; want false")
	}
}

func TestIfaceSetRuleMatch(t *testing.T) {
	ifaceSet := set.NewIfaceSet()
	_ = ifaceSet.Add("eth0")
	_ = ifaceSet.Add("eth1")

	pktIngressEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktIngressEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))
	pktIngressEth2 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.3"), packet.WithIngressIface("eth2"))
	pktNoIface := mustNewPacket(t, packet.WithSrcAddr("10.0.0.4"))

	// IfaceSet on Source — matches against ingress iface.
	rSrc := mustNew(WithSrcSet(ifaceSet))
	if !rSrc.Match(pktIngressEth0) {
		t.Error("rSrc.Match(pktIngressEth0) = false; want true")
	}
	if !rSrc.Match(pktIngressEth1) {
		t.Error("rSrc.Match(pktIngressEth1) = false; want true")
	}
	if rSrc.Match(pktIngressEth2) {
		t.Error("rSrc.Match(pktIngressEth2) = true; want false")
	}
	if rSrc.Match(pktNoIface) {
		t.Error("rSrc.Match(pktNoIface) = true; want false")
	}

	pktEgressEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEgressEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))
	pktEgressEth2 := mustNewPacket(t, packet.WithDstAddr("10.0.0.3"), packet.WithEgressIface("eth2"))

	// IfaceSet on Destination — matches against egress iface.
	rDst := mustNew(WithDstSet(ifaceSet))
	if !rDst.Match(pktEgressEth0) {
		t.Error("rDst.Match(pktEgressEth0) = false; want true")
	}
	if !rDst.Match(pktEgressEth1) {
		t.Error("rDst.Match(pktEgressEth1) = false; want true")
	}
	if rDst.Match(pktEgressEth2) {
		t.Error("rDst.Match(pktEgressEth2) = true; want false")
	}
}

func TestNotIfaceSetRuleMatch(t *testing.T) {
	ifaceSet := set.NewIfaceSet()
	_ = ifaceSet.Add("eth0")

	pktIngressEth0 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.1"), packet.WithIngressIface("eth0"))
	pktIngressEth1 := mustNewPacket(t, packet.WithSrcAddr("10.0.0.2"), packet.WithIngressIface("eth1"))

	// NotSrcIfaceSet: packets on ingress eth0 should NOT match.
	rNotSrc := mustNew(WithNotSrcSet(ifaceSet))
	if rNotSrc.Match(pktIngressEth0) {
		t.Error("rNotSrc.Match(pktIngressEth0) = true; want false")
	}
	if !rNotSrc.Match(pktIngressEth1) {
		t.Error("rNotSrc.Match(pktIngressEth1) = false; want true")
	}

	pktEgressEth0 := mustNewPacket(t, packet.WithDstAddr("10.0.0.1"), packet.WithEgressIface("eth0"))
	pktEgressEth1 := mustNewPacket(t, packet.WithDstAddr("10.0.0.2"), packet.WithEgressIface("eth1"))

	// NotDstIfaceSet: packets on egress eth0 should NOT match.
	rNotDst := mustNew(WithNotDstSet(ifaceSet))
	if rNotDst.Match(pktEgressEth0) {
		t.Error("rNotDst.Match(pktEgressEth0) = true; want false")
	}
	if !rNotDst.Match(pktEgressEth1) {
		t.Error("rNotDst.Match(pktEgressEth1) = false; want true")
	}
}
