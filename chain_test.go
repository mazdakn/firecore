package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/packet"
	. "github.com/onsi/gomega"
)

func TestNewChainEmptyNameFails(t *testing.T) {
	RegisterTestingT(t)

	chain, err := NewChain("")
	Expect(err).To(HaveOccurred())
	Expect(chain).To(BeNil())
}

func TestChainAddRuleSortAscending(t *testing.T) {
	RegisterTestingT(t)

	chain := newChain("main")

	rule1 := newRule(WithName("rule1"), WithOrder(10), WithAction(Accept))
	rule2 := newRule(WithName("rule2"), WithOrder(30), WithAction(Accept))
	rule3 := newRule(WithName("rule3"), WithOrder(20), WithAction(Accept))

	Expect(chain.AddRule(rule1)).To(Succeed())
	Expect(chain.AddRule(rule2)).To(Succeed())
	Expect(chain.AddRule(rule3)).To(Succeed())

	Expect(chain.Rules).To(HaveLen(3))
	Expect(chain.Rules[0].Order).To(Equal(uint64(10)))
	Expect(chain.Rules[1].Order).To(Equal(uint64(20)))
	Expect(chain.Rules[2].Order).To(Equal(uint64(30)))
}

func TestChainAddRuleSortStableForEqualOrders(t *testing.T) {
	RegisterTestingT(t)

	chain := newChain("main")

	rule1 := newRule(WithName("rule1"), WithAction(Accept))
	rule2 := newRule(WithName("rule2"), WithAction(Drop))
	rule3 := newRule(WithName("rule3"), WithAction(Accept))

	Expect(chain.AddRule(rule1)).To(Succeed())
	Expect(chain.AddRule(rule2)).To(Succeed())
	Expect(chain.AddRule(rule3)).To(Succeed())

	Expect(chain.Rules).To(HaveLen(3))
	Expect(chain.Rules[0].Name).To(Equal("rule1"))
	Expect(chain.Rules[1].Name).To(Equal("rule2"))
	Expect(chain.Rules[2].Name).To(Equal("rule3"))
}

func TestChainAddRuleNilFails(t *testing.T) {
	RegisterTestingT(t)

	chain := newChain("main")
	Expect(chain.AddRule(nil)).To(HaveOccurred())
}

func TestChainAddRuleDuplicateNameFails(t *testing.T) {
	RegisterTestingT(t)

	chain := newChain("main")
	rule1 := newRule(WithName("dup"), WithAction(Accept))
	rule2 := newRule(WithName("dup"), WithAction(Drop))

	Expect(chain.AddRule(rule1)).To(Succeed())
	Expect(chain.AddRule(rule2)).To(HaveOccurred())
	Expect(chain.Rules).To(HaveLen(1))
}

func TestChainAddRuleAllowsRepeatedAnonymousRules(t *testing.T) {
	RegisterTestingT(t)

	chain := newChain("main")
	rule1 := newRule(WithAction(Accept))
	rule2 := newRule(WithAction(Drop))

	Expect(chain.AddRule(rule1)).To(Succeed())
	Expect(chain.AddRule(rule2)).To(Succeed())
	Expect(chain.Rules).To(HaveLen(2))
}

func TestTableJumpToChainAndReturn(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: accept HTTP traffic
	helperChain := newChain("helper")
	acceptHTTP := newRule(WithName("accept-http"), WithOrder(1), WithAction(Accept),
		WithProto(6), WithDstPort(80))
	Expect(helperChain.AddRule(acceptHTTP)).To(Succeed())

	// entry chain: jump to helper for TCP traffic
	mainChain := newChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	Expect(mainChain.AddRule(jumpRule)).To(Succeed())

	Expect(tbl.AddChain(mainChain)).To(Succeed())
	Expect(tbl.AddChain(helperChain)).To(Succeed())

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	Expect(matched).To(BeTrue())
	Expect(err).NotTo(HaveOccurred())
	Expect(result.Verdict).To(HaveValue(Equal(Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("jump-to-helper"))
	Expect(result.Trace[1].Name).To(Equal("accept-http"))
}

func TestTableJumpChainNoMatchReturnsToCaller(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: only matches port 443 — will not match the packet
	helperChain := newChain("helper")
	noMatchRule := newRule(WithName("accept-https"), WithOrder(1), WithAction(Accept),
		WithProto(6), WithDstPort(443))
	Expect(helperChain.AddRule(noMatchRule)).To(Succeed())

	// entry chain: jump to helper, then fall through to default action
	mainChain := newChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	Expect(mainChain.AddRule(jumpRule)).To(Succeed())

	Expect(tbl.AddChain(mainChain)).To(Succeed())
	Expect(tbl.AddChain(helperChain)).To(Succeed())

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	// helper chain returned, entry chain fell through → default Drop
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(Drop)))
}

func TestTableReturnActionReturnsToCallerChain(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: Return immediately
	helperChain := newChain("helper")
	returnRule := newRule(WithName("return-all"), WithOrder(1), WithAction(Return))
	Expect(helperChain.AddRule(returnRule)).To(Succeed())

	// entry chain: jump to helper, then accept all
	mainChain := newChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	acceptAll := newRule(WithName("accept-all"), WithOrder(2), WithAction(Accept))
	Expect(mainChain.AddRule(jumpRule)).To(Succeed())
	Expect(mainChain.AddRule(acceptAll)).To(Succeed())

	Expect(tbl.AddChain(mainChain)).To(Succeed())
	Expect(tbl.AddChain(helperChain)).To(Succeed())

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	// Return in helper → continues in main after jump-to-helper → accept-all
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(Accept)))
	Expect(result.Trace[len(result.Trace)-1].Name).To(Equal("accept-all"))
}

func TestTableMatchReturnsErrorForMissingJumpTarget(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(
		WithName("jump-missing"),
		WithJump("missing"),
	))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	Expect(err).To(MatchError(`chain "missing" not found`))
	Expect(matched).To(BeFalse())
	Expect(result.Trace).To(HaveLen(1))
	Expect(result.Trace[0].Name).To(Equal("jump-missing"))
}

func TestTableMatchReturnsErrorWhenJumpDepthExceeded(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	// A direct cycle that Validate was not called to catch; Match must fail
	// safe via the depth limit instead of recursing until a stack overflow.
	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper")))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	helperChain := newChain("helper")
	Expect(helperChain.AddRule(newRule(WithName("jump-to-main"), WithJump("main")))).To(Succeed())
	Expect(tbl.AddChain(helperChain)).To(Succeed())

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)
	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	Expect(matched).To(BeFalse())
	Expect(err).To(MatchError(ContainSubstring("jump depth exceeded")))
}
