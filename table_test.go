package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/packet"
	. "github.com/onsi/gomega"
)

func TestNewTableEmptyNameFails(t *testing.T) {
	RegisterTestingT(t)

	tbl, err := NewTable("", 0, Drop)
	Expect(err).To(HaveOccurred())
	Expect(tbl).To(BeNil())
}

func TestAddChainNilFails(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	Expect(tbl.AddChain(nil)).To(HaveOccurred())
}

func TestNewChainEmptyNameFails(t *testing.T) {
	RegisterTestingT(t)

	chain, err := NewChain("")
	Expect(err).To(HaveOccurred())
	Expect(chain).To(BeNil())
}

// TestAddChainEmptyNameFails constructs a Chain literal directly, bypassing
// NewChain's own empty-name check, to verify AddChain's defense-in-depth
// check still rejects it.
func TestAddChainEmptyNameFails(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	Expect(tbl.AddChain(&Chain{Name: ""})).To(HaveOccurred())
}

func TestAddChainDuplicateNameFails(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	chain1, err := NewChain("main")
	Expect(err).ToNot(HaveOccurred())
	Expect(tbl.AddChain(chain1)).To(Succeed())

	chain2, err := NewChain("main")
	Expect(err).ToNot(HaveOccurred())
	Expect(tbl.AddChain(chain2)).To(HaveOccurred())
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

func TestSetEntryChainUnknownNameFails(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	Expect(tbl.SetEntryChain("missing")).To(HaveOccurred())
	Expect(tbl.EntryChain()).To(Equal(""))
}

func TestSetEntryChainKnownNameSucceeds(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	Expect(tbl.AddChain(newChain("main"))).To(Succeed())
	Expect(tbl.AddChain(newChain("other"))).To(Succeed())

	Expect(tbl.SetEntryChain("other")).To(Succeed())
	Expect(tbl.EntryChain()).To(Equal("other"))
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
	chain := newChain("main")

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	highOrderDrop := newRule(WithName("high-drop"), WithOrder(100), WithAction(Drop),
		WithProto(6), WithDstPort(80))
	lowOrderAccept := newRule(WithName("low-accept"), WithOrder(1), WithAction(Accept),
		WithProto(6), WithDstPort(80))

	Expect(chain.AddRule(highOrderDrop)).To(Succeed())
	Expect(chain.AddRule(lowOrderAccept)).To(Succeed())
	Expect(tbl.AddChain(chain)).To(Succeed())

	result := &Result{}
	matched, err := tbl.Match(pkt, result)
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(Accept)))
}

func TestTableMatchPassRuleDoesNotEvaluateDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	chain := newChain("main")

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	passRule := newRule(WithName("pass-http"), WithOrder(1), WithAction(Pass),
		WithProto(6), WithDstPort(80))

	Expect(chain.AddRule(passRule)).To(Succeed())
	Expect(tbl.AddChain(chain)).To(Succeed())

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
	chain := newChain("main")
	Expect(tbl.AddChain(chain)).To(Succeed())

	pkt := mustNewPacket(t,
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

func TestTableMatchNilDefaultRuleReturnsNoMatch(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	tbl.DefaultRule = nil
	chain := newChain("main")
	Expect(tbl.AddChain(chain)).To(Succeed())

	pkt := mustNewPacket(t,
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

func TestTableValidateReturnsErrorForMissingJumpTarget(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(
		WithName("jump-missing"),
		WithJump("missing"),
	))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	Expect(tbl.Validate()).To(MatchError(`chain "main": rule "jump-missing" jumps to undefined chain "missing"`))
}

func TestTableValidateAllowsForwardReferencedChains(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	// mainChain jumps to "helper" before helperChain has been created or
	// added to the table — this forward reference must remain valid.
	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper")))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	Expect(tbl.Validate()).To(MatchError(`chain "main": rule "jump-to-helper" jumps to undefined chain "helper"`))

	helperChain := newChain("helper")
	Expect(helperChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept)))).To(Succeed())
	Expect(tbl.AddChain(helperChain)).To(Succeed())

	Expect(tbl.Validate()).NotTo(HaveOccurred())
}

func TestTableValidateReturnsNilForNoJumpRules(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)
	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept)))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	Expect(tbl.Validate()).NotTo(HaveOccurred())
}

func TestTableValidateDetectsDirectCycle(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper")))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	helperChain := newChain("helper")
	Expect(helperChain.AddRule(newRule(WithName("jump-to-main"), WithJump("main")))).To(Succeed())
	Expect(tbl.AddChain(helperChain)).To(Succeed())

	Expect(tbl.Validate()).To(MatchError(
		`chain "main": rule "jump-to-helper" creates a jump cycle: helper -> main -> helper`,
	))
}

func TestTableValidateDetectsSelfLoop(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(WithName("jump-to-self"), WithJump("main")))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	Expect(tbl.Validate()).To(MatchError(
		`chain "main": rule "jump-to-self" creates a jump cycle: main -> main`,
	))
}

func TestTableValidateAllowsDiamondJumps(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("test", 0, Drop)

	// main jumps to both left and right, which both jump to shared — not a
	// cycle, just two paths converging on the same chain.
	mainChain := newChain("main")
	Expect(mainChain.AddRule(newRule(WithName("jump-left"), WithOrder(1), WithJump("left")))).To(Succeed())
	Expect(mainChain.AddRule(newRule(WithName("jump-right"), WithOrder(2), WithJump("right")))).To(Succeed())
	Expect(tbl.AddChain(mainChain)).To(Succeed())

	leftChain := newChain("left")
	Expect(leftChain.AddRule(newRule(WithName("left-to-shared"), WithJump("shared")))).To(Succeed())
	Expect(tbl.AddChain(leftChain)).To(Succeed())

	rightChain := newChain("right")
	Expect(rightChain.AddRule(newRule(WithName("right-to-shared"), WithJump("shared")))).To(Succeed())
	Expect(tbl.AddChain(rightChain)).To(Succeed())

	sharedChain := newChain("shared")
	Expect(sharedChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept)))).To(Succeed())
	Expect(tbl.AddChain(sharedChain)).To(Succeed())

	Expect(tbl.Validate()).NotTo(HaveOccurred())
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
