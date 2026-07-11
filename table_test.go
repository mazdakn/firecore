package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/packet"
	. "github.com/onsi/gomega"
)

func TestChainAddRuleSortAscending(t *testing.T) {
	RegisterTestingT(t)

	chain := NewChain("main")

	rule1 := newRule(WithName("rule1"), WithOrder(10), WithAction(Accept))
	rule2 := newRule(WithName("rule2"), WithOrder(30), WithAction(Accept))
	rule3 := newRule(WithName("rule3"), WithOrder(20), WithAction(Accept))

	chain.AddRule(rule1)
	chain.AddRule(rule2)
	chain.AddRule(rule3)

	Expect(chain.Rules).To(HaveLen(3))
	Expect(chain.Rules[0].Order).To(Equal(uint64(10)))
	Expect(chain.Rules[1].Order).To(Equal(uint64(20)))
	Expect(chain.Rules[2].Order).To(Equal(uint64(30)))
}

func TestChainAddRuleSortStableForEqualOrders(t *testing.T) {
	RegisterTestingT(t)

	chain := NewChain("main")

	rule1 := newRule(WithName("rule1"), WithAction(Accept))
	rule2 := newRule(WithName("rule2"), WithAction(Drop))
	rule3 := newRule(WithName("rule3"), WithAction(Accept))

	chain.AddRule(rule1)
	chain.AddRule(rule2)
	chain.AddRule(rule3)

	Expect(chain.Rules).To(HaveLen(3))
	Expect(chain.Rules[0].Name).To(Equal("rule1"))
	Expect(chain.Rules[1].Name).To(Equal("rule2"))
	Expect(chain.Rules[2].Name).To(Equal("rule3"))
}

func TestSortTablesSortAscendingAndStable(t *testing.T) {
	RegisterTestingT(t)

	t1 := newTable("first", 10, Accept)
	t2 := newTable("second", 0, Accept)
	t3 := newTable("third", 10, Accept)
	t4 := newTable("fourth", 5, Accept)

	tables := []*Table{t1, t2, t3, t4}
	SortTables(tables)

	Expect(tables[0].Name).To(Equal("second"))
	Expect(tables[1].Name).To(Equal("fourth"))
	Expect(tables[2].Name).To(Equal("first"))
	Expect(tables[3].Name).To(Equal("third"))
}

func TestTableMatchUsesAscendingOrder(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	chain := NewChain("main")

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	highOrderDrop := newRule(WithName("high-drop"), WithOrder(100), WithAction(Drop),
		WithProto(6), WithDstPort(80))
	lowOrderAccept := newRule(WithName("low-accept"), WithOrder(1), WithAction(Accept),
		WithProto(6), WithDstPort(80))

	chain.AddRule(highOrderDrop)
	chain.AddRule(lowOrderAccept)
	tbl.AddChain(chain)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(Accept)))
}

func TestTableMatchPassRuleDoesNotEvaluateDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	chain := NewChain("main")

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	passRule := newRule(WithName("pass-http"), WithOrder(1), WithAction(Pass),
		WithProto(6), WithDstPort(80))

	chain.AddRule(passRule)
	tbl.AddChain(chain)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeFalse())
	Expect(result.Verdict).To(HaveValue(Equal(Pass)))
	Expect(result.Trace).To(HaveLen(1))
	Expect(result.Trace[0].Name).To(Equal("pass-http"))
}

func TestTableMatchNoRuleAndDefaultPassReturnsNoMatchVerdict(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Pass)
	chain := NewChain("main")
	tbl.AddChain(chain)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeFalse())
	Expect(result.Verdict).To(BeNil())
	Expect(result.Trace).To(HaveLen(1))
	Expect(result.Trace[0].Name).To(Equal("table test default action"))
	Expect(result.Trace[0].Action).To(Equal(Pass))
}

func TestTableJumpToChainAndReturn(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: accept HTTP traffic
	helperChain := NewChain("helper")
	acceptHTTP := newRule(WithName("accept-http"), WithOrder(1), WithAction(Accept),
		WithProto(6), WithDstPort(80))
	helperChain.AddRule(acceptHTTP)

	// entry chain: jump to helper for TCP traffic
	mainChain := NewChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	mainChain.AddRule(jumpRule)

	tbl.AddChain(mainChain)
	tbl.AddChain(helperChain)

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

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: only matches port 443 — will not match the packet
	helperChain := NewChain("helper")
	noMatchRule := newRule(WithName("accept-https"), WithOrder(1), WithAction(Accept),
		WithProto(6), WithDstPort(443))
	helperChain.AddRule(noMatchRule)

	// entry chain: jump to helper, then fall through to default action
	mainChain := NewChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	mainChain.AddRule(jumpRule)

	tbl.AddChain(mainChain)
	tbl.AddChain(helperChain)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	// helper chain returned, entry chain fell through → default Drop
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(Drop)))
}

func TestTableMatchNilDefaultRuleReturnsNoMatch(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	tbl.DefaultRule = nil
	chain := NewChain("main")
	tbl.AddChain(chain)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeFalse())
	Expect(result.Verdict).To(BeNil())
	Expect(result.Trace).To(BeEmpty())
}

func TestTableReturnActionReturnsToCallerChain(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: Return immediately
	helperChain := NewChain("helper")
	returnRule := newRule(WithName("return-all"), WithOrder(1), WithAction(Return))
	helperChain.AddRule(returnRule)

	// entry chain: jump to helper, then accept all
	mainChain := NewChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	acceptAll := newRule(WithName("accept-all"), WithOrder(2), WithAction(Accept))
	mainChain.AddRule(jumpRule)
	mainChain.AddRule(acceptAll)

	tbl.AddChain(mainChain)
	tbl.AddChain(helperChain)

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

	mainChain := NewChain("main")
	mainChain.AddRule(newRule(
		WithName("jump-missing"),
		WithJump("missing"),
	))
	tbl.AddChain(mainChain)

	pkt := packet.New(
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

func TestTableValidateReturnsErrorForMissingJumpTarget(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	mainChain := NewChain("main")
	mainChain.AddRule(newRule(
		WithName("jump-missing"),
		WithJump("missing"),
	))
	tbl.AddChain(mainChain)

	Expect(tbl.Validate()).To(MatchError(`chain "main": rule "jump-missing" jumps to undefined chain "missing"`))
}

func TestTableValidateAllowsForwardReferencedChains(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	// mainChain jumps to "helper" before helperChain has been created or
	// added to the table — this forward reference must remain valid.
	mainChain := NewChain("main")
	mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper")))
	tbl.AddChain(mainChain)

	Expect(tbl.Validate()).To(MatchError(`chain "main": rule "jump-to-helper" jumps to undefined chain "helper"`))

	helperChain := NewChain("helper")
	helperChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept)))
	tbl.AddChain(helperChain)

	Expect(tbl.Validate()).NotTo(HaveOccurred())
}

func TestTableValidateReturnsNilForNoJumpRules(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	mainChain := NewChain("main")
	mainChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept)))
	tbl.AddChain(mainChain)

	Expect(tbl.Validate()).NotTo(HaveOccurred())
}

func TestTableValidateDetectsDirectCycle(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	mainChain := NewChain("main")
	mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper")))
	tbl.AddChain(mainChain)

	helperChain := NewChain("helper")
	helperChain.AddRule(newRule(WithName("jump-to-main"), WithJump("main")))
	tbl.AddChain(helperChain)

	Expect(tbl.Validate()).To(MatchError(
		`chain "main": rule "jump-to-helper" creates a jump cycle: helper -> main -> helper`,
	))
}

func TestTableValidateDetectsSelfLoop(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	mainChain := NewChain("main")
	mainChain.AddRule(newRule(WithName("jump-to-self"), WithJump("main")))
	tbl.AddChain(mainChain)

	Expect(tbl.Validate()).To(MatchError(
		`chain "main": rule "jump-to-self" creates a jump cycle: main -> main`,
	))
}

func TestTableValidateAllowsDiamondJumps(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	// main jumps to both left and right, which both jump to shared — not a
	// cycle, just two paths converging on the same chain.
	mainChain := NewChain("main")
	mainChain.AddRule(newRule(WithName("jump-left"), WithOrder(1), WithJump("left")))
	mainChain.AddRule(newRule(WithName("jump-right"), WithOrder(2), WithJump("right")))
	tbl.AddChain(mainChain)

	leftChain := NewChain("left")
	leftChain.AddRule(newRule(WithName("left-to-shared"), WithJump("shared")))
	tbl.AddChain(leftChain)

	rightChain := NewChain("right")
	rightChain.AddRule(newRule(WithName("right-to-shared"), WithJump("shared")))
	tbl.AddChain(rightChain)

	sharedChain := NewChain("shared")
	sharedChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept)))
	tbl.AddChain(sharedChain)

	Expect(tbl.Validate()).NotTo(HaveOccurred())
}

func TestTableMatchReturnsErrorWhenJumpDepthExceeded(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	// A direct cycle that Validate was not called to catch; Match must fail
	// safe via the depth limit instead of recursing until a stack overflow.
	mainChain := NewChain("main")
	mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper")))
	tbl.AddChain(mainChain)

	helperChain := NewChain("helper")
	helperChain.AddRule(newRule(WithName("jump-to-main"), WithJump("main")))
	tbl.AddChain(helperChain)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)
	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	Expect(matched).To(BeFalse())
	Expect(err).To(MatchError(ContainSubstring("jump depth exceeded")))
}
