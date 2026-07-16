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
