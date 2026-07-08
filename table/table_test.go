package table

import (
	"testing"

	"github.com/mazdakn/firecore/eval"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/rule"
	. "github.com/onsi/gomega"
)

func TestChainAddRuleSortAscending(t *testing.T) {
	RegisterTestingT(t)

	chain := NewChain("main")

	rule1 := rule.New(rule.WithName("rule1"), rule.WithOrder(10), rule.WithAction(rule.Accept))
	rule2 := rule.New(rule.WithName("rule2"), rule.WithOrder(30), rule.WithAction(rule.Accept))
	rule3 := rule.New(rule.WithName("rule3"), rule.WithOrder(20), rule.WithAction(rule.Accept))

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

	rule1 := rule.New(rule.WithName("rule1"), rule.WithAction(rule.Accept))
	rule2 := rule.New(rule.WithName("rule2"), rule.WithAction(rule.Drop))
	rule3 := rule.New(rule.WithName("rule3"), rule.WithAction(rule.Accept))

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

	t1 := New("first", 10, rule.Accept)
	t2 := New("second", 0, rule.Accept)
	t3 := New("third", 10, rule.Accept)
	t4 := New("fourth", 5, rule.Accept)

	tables := []*Table{t1, t2, t3, t4}
	SortTables(tables)

	Expect(tables[0].Name).To(Equal("second"))
	Expect(tables[1].Name).To(Equal("fourth"))
	Expect(tables[2].Name).To(Equal("first"))
	Expect(tables[3].Name).To(Equal("third"))
}

func TestTableMatchUsesAscendingOrder(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)
	chain := NewChain("main")

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	highOrderDrop := rule.New(rule.WithName("high-drop"), rule.WithOrder(100), rule.WithAction(rule.Drop),
		rule.WithProto(6), rule.WithDstPort(80))
	lowOrderAccept := rule.New(rule.WithName("low-accept"), rule.WithOrder(1), rule.WithAction(rule.Accept),
		rule.WithProto(6), rule.WithDstPort(80))

	chain.AddRule(highOrderDrop)
	chain.AddRule(lowOrderAccept)
	tbl.AddChain(chain)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Accept)))
}

func TestTableMatchPassContinuesToNextTable(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)
	chain := NewChain("main")

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	passRule := rule.New(rule.WithName("pass-http"), rule.WithOrder(1), rule.WithAction(rule.Pass),
		rule.WithProto(6), rule.WithDstPort(80))
	chain.AddRule(passRule)
	tbl.AddChain(chain)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeFalse())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Pass)))
	Expect(result.Trace).To(HaveLen(1))
	Expect(result.Trace[0].Name).To(Equal("pass-http"))
}

func TestTableMatchPassRuleDoesNotEvaluateDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)
	chain := NewChain("main")

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	passRule := rule.New(rule.WithName("pass-http"), rule.WithOrder(1), rule.WithAction(rule.Pass),
		rule.WithProto(6), rule.WithDstPort(80))

	chain.AddRule(passRule)
	tbl.AddChain(chain)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeFalse())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Pass)))
	Expect(result.Trace).To(HaveLen(1))
	Expect(result.Trace[0].Name).To(Equal("pass-http"))
}

func TestTableMatchNoRuleAndDefaultPassReturnsNoMatchVerdict(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Pass)
	chain := NewChain("main")
	tbl.AddChain(chain)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeFalse())
	Expect(result.Verdict).To(BeNil())
	Expect(result.Trace).To(HaveLen(1))
	Expect(result.Trace[0].Name).To(Equal("table test default action"))
	Expect(result.Trace[0].Action).To(Equal(rule.Pass))
}

func TestTableJumpToChainAndReturn(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: accept HTTP traffic
	helperChain := NewChain("helper")
	acceptHTTP := rule.New(rule.WithName("accept-http"), rule.WithOrder(1), rule.WithAction(rule.Accept),
		rule.WithProto(6), rule.WithDstPort(80))
	helperChain.AddRule(acceptHTTP)

	// entry chain: jump to helper for TCP traffic
	mainChain := NewChain("main")
	jumpRule := rule.New(rule.WithName("jump-to-helper"), rule.WithOrder(1),
		rule.WithJump("helper"), rule.WithProto(6))
	mainChain.AddRule(jumpRule)

	tbl.AddChain(mainChain)
	tbl.AddChain(helperChain)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	Expect(matched).To(BeTrue())
	Expect(err).NotTo(HaveOccurred())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("jump-to-helper"))
	Expect(result.Trace[1].Name).To(Equal("accept-http"))
}

func TestTableJumpChainNoMatchReturnsToCaller(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: only matches port 443 — will not match the packet
	helperChain := NewChain("helper")
	noMatchRule := rule.New(rule.WithName("accept-https"), rule.WithOrder(1), rule.WithAction(rule.Accept),
		rule.WithProto(6), rule.WithDstPort(443))
	helperChain.AddRule(noMatchRule)

	// entry chain: jump to helper, then fall through to default action
	mainChain := NewChain("main")
	jumpRule := rule.New(rule.WithName("jump-to-helper"), rule.WithOrder(1),
		rule.WithJump("helper"), rule.WithProto(6))
	mainChain.AddRule(jumpRule)

	tbl.AddChain(mainChain)
	tbl.AddChain(helperChain)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	// helper chain returned, entry chain fell through → default Drop
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Drop)))
}

func TestTableMatchNilDefaultRuleReturnsNoMatch(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)
	tbl.DefaultRule = nil
	chain := NewChain("main")
	tbl.AddChain(chain)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeFalse())
	Expect(result.Verdict).To(BeNil())
	Expect(result.Trace).To(BeEmpty())
}

func TestTableReturnActionReturnsToCallerChain(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	// helper chain: Return immediately
	helperChain := NewChain("helper")
	returnRule := rule.New(rule.WithName("return-all"), rule.WithOrder(1), rule.WithAction(rule.Return))
	helperChain.AddRule(returnRule)

	// entry chain: jump to helper, then accept all
	mainChain := NewChain("main")
	jumpRule := rule.New(rule.WithName("jump-to-helper"), rule.WithOrder(1),
		rule.WithJump("helper"), rule.WithProto(6))
	acceptAll := rule.New(rule.WithName("accept-all"), rule.WithOrder(2), rule.WithAction(rule.Accept))
	mainChain.AddRule(jumpRule)
	mainChain.AddRule(acceptAll)

	tbl.AddChain(mainChain)
	tbl.AddChain(helperChain)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	// Return in helper → continues in main after jump-to-helper → accept-all
	Expect(err).NotTo(HaveOccurred())
	Expect(matched).To(BeTrue())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(result.Trace[len(result.Trace)-1].Name).To(Equal("accept-all"))
}

func TestTableMatchReturnsErrorForMissingJumpTarget(t *testing.T) {
	RegisterTestingT(t)

	tbl := New("test", 0, rule.Drop)

	mainChain := NewChain("main")
	mainChain.AddRule(rule.New(
		rule.WithName("jump-missing"),
		rule.WithJump("missing"),
	))
	tbl.AddChain(mainChain)

	pkt := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)

	mc := eval.Context{Packet: pkt}
	result := &eval.Result{}
	matched, err := tbl.Match(&mc, result)

	Expect(err).To(MatchError(`chain "missing" not found`))
	Expect(matched).To(BeFalse())
	Expect(result.Trace).To(HaveLen(1))
	Expect(result.Trace[0].Name).To(Equal("jump-missing"))
}
