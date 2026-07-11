package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/rule"
	. "github.com/onsi/gomega"
)

func expectMatchResult(result *Result, expectedVerdict rule.Action, expectedRule string) {
	Expect(result.Verdict).To(HaveValue(Equal(expectedVerdict)))
	Expect(result.Trace).NotTo(BeEmpty())
	Expect(result.Trace[len(result.Trace)-1].Name).To(Equal(expectedRule))
}

func newRule(opts ...rule.RuleOption) *rule.Rule {
	r, err := rule.New(opts...)
	Expect(err).NotTo(HaveOccurred())
	return r
}

func newTable(name string, order uint64, defaultAction rule.Action) *Table {
	tbl, err := NewTable(name, order, defaultAction)
	Expect(err).NotTo(HaveOccurred())
	return tbl
}

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	Expect(engine).ToNot(BeNil())
	Expect(engine.Tables).To(BeNil())
	Expect(engine.tracker).To(BeNil())
}

func TestNewAppliesOptions(t *testing.T) {
	RegisterTestingT(t)

	engine := New(WithConntrack())

	Expect(engine.Tables).To(BeNil())
	Expect(engine.tracker).NotTo(BeNil())
}

func TestAddTable(t *testing.T) {
	RegisterTestingT(t)

	first := newTable("first", 1, rule.Drop)
	second := newTable("second", 2, rule.Drop)
	engine := New()

	engine.AddTable(first)
	engine.AddTable(second)

	Expect(engine.Tables).To(Equal([]*Table{first, second}))
}

func TestEvaluateSortsTablesByAscendingOrder(t *testing.T) {
	RegisterTestingT(t)

	acceptTable := newTable("accept-table", 2, rule.Drop)
	acceptChain := NewChain("default")
	acceptChain.AddRule(newRule(
		rule.WithName("accept-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	acceptTable.AddChain(acceptChain)

	passTable := newTable("pass-table", 1, rule.Drop)
	passChain := NewChain("default")
	passChain.AddRule(newRule(
		rule.WithName("pass-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Pass),
	))
	passTable.AddChain(passChain)

	engine := New()
	engine.AddTable(acceptTable)
	engine.AddTable(passTable)

	result, err := engine.Evaluate(packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	))

	Expect(err).NotTo(HaveOccurred())
	Expect(engine.Tables).To(Equal([]*Table{passTable, acceptTable}))
	Expect(result.Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("pass-http"))
	Expect(result.Trace[1].Name).To(Equal("accept-http"))
}

func TestEvaluatePassesToNextTable(t *testing.T) {
	RegisterTestingT(t)

	passTable := newTable("pass-table", 1, rule.Drop)
	passChain := NewChain("default")
	passChain.AddRule(newRule(
		rule.WithName("pass-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Pass),
	))
	passTable.AddChain(passChain)

	acceptTable := newTable("accept-table", 2, rule.Drop)
	acceptChain := NewChain("default")
	acceptChain.AddRule(newRule(
		rule.WithName("accept-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	acceptTable.AddChain(acceptChain)

	engine := New()
	engine.AddTable(passTable)
	engine.AddTable(acceptTable)

	result, err := engine.Evaluate(packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	))

	Expect(err).NotTo(HaveOccurred())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("pass-http"))
	Expect(result.Trace[1].Name).To(Equal("accept-http"))
}

func TestEvaluateTracksEstablishedFlows(t *testing.T) {
	RegisterTestingT(t)

	stateful := newTable("stateful", 1, rule.Drop)
	defaultChain := NewChain("default")
	defaultChain.AddRule(newRule(
		rule.WithName("allow-new-http"),
		rule.WithConnState(conntrack.StateNew),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	defaultChain.AddRule(newRule(
		rule.WithName("allow-established"),
		rule.WithConnState(conntrack.StateEstablished),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	stateful.AddChain(defaultChain)

	request := packet.New(
		packet.WithName("request"),
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	reply := packet.New(
		packet.WithName("reply"),
		packet.WithSrcAddr("1.1.1.1"),
		packet.WithDstAddr("10.0.0.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(80),
		packet.WithDstPort(12345),
	)

	engine := New(WithConntrack())
	engine.AddTable(stateful)

	requestResult, err := engine.Evaluate(request)
	Expect(err).NotTo(HaveOccurred())
	replyResult, err := engine.Evaluate(reply)

	Expect(err).NotTo(HaveOccurred())
	Expect(requestResult.ConnState).To(HaveValue(Equal(conntrack.StateNew)))
	expectMatchResult(requestResult, rule.Accept, "allow-new-http")
	Expect(replyResult.ConnState).To(HaveValue(Equal(conntrack.StateEstablished)))
	expectMatchResult(replyResult, rule.Accept, "allow-established")
}

func TestEvaluateWithoutConntrackDisablesStatefulMatching(t *testing.T) {
	RegisterTestingT(t)

	stateful := newTable("stateful", 1, rule.Drop)
	defaultChain := NewChain("default")
	defaultChain.AddRule(newRule(
		rule.WithName("allow-new-http"),
		rule.WithConnState(conntrack.StateNew),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	defaultChain.AddRule(newRule(
		rule.WithName("allow-established"),
		rule.WithConnState(conntrack.StateEstablished),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	stateful.AddChain(defaultChain)

	request := packet.New(
		packet.WithName("request"),
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	reply := packet.New(
		packet.WithName("reply"),
		packet.WithSrcAddr("1.1.1.1"),
		packet.WithDstAddr("10.0.0.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(80),
		packet.WithDstPort(12345),
	)

	engine := New()
	engine.AddTable(stateful)

	requestResult, err := engine.Evaluate(request)
	Expect(err).NotTo(HaveOccurred())
	replyResult, err := engine.Evaluate(reply)

	Expect(err).NotTo(HaveOccurred())
	Expect(requestResult.ConnState).To(BeNil())
	expectMatchResult(requestResult, rule.Accept, "allow-new-http")
	Expect(replyResult.ConnState).To(BeNil())
	expectMatchResult(replyResult, rule.Drop, "table stateful default action")
}

func TestEvaluateSupportsJumpChains(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("main", 1, rule.Drop)
	entry := NewChain("entry")
	entry.AddRule(newRule(
		rule.WithName("jump-admin"),
		rule.WithSrcNet("10.0.0.0/8"),
		rule.WithJump("admin"),
	))
	entry.AddRule(newRule(
		rule.WithName("deny-all"),
		rule.WithAction(rule.Drop),
	))
	admin := NewChain("admin")
	admin.AddRule(newRule(
		rule.WithName("allow-admin-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	tbl.AddChain(entry)
	tbl.AddChain(admin)
	tbl.SetEntryChain("entry")

	engine := New()
	engine.AddTable(tbl)

	result, err := engine.Evaluate(packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	))

	Expect(err).NotTo(HaveOccurred())
	Expect(result.Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("jump-admin"))
	Expect(result.Trace[1].Name).To(Equal("allow-admin-http"))
}

func TestEvaluateReturnsErrorForMissingJumpTarget(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("main", 1, rule.Drop)
	entry := NewChain("entry")
	entry.AddRule(newRule(
		rule.WithName("jump-missing"),
		rule.WithJump("missing"),
	))
	tbl.AddChain(entry)
	tbl.SetEntryChain("entry")

	engine := New()
	engine.AddTable(tbl)

	result, err := engine.Evaluate(packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	))

	Expect(err).To(MatchError(`evaluate in table "main": chain "missing" not found`))
	Expect(result).To(BeNil())
}
