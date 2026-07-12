package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	. "github.com/onsi/gomega"
)

func expectMatchResult(result *Result, expectedVerdict Action, expectedRule string) {
	Expect(result.Verdict).To(HaveValue(Equal(expectedVerdict)))
	Expect(result.Trace).NotTo(BeEmpty())
	Expect(result.Trace[len(result.Trace)-1].Name).To(Equal(expectedRule))
}

func newRule(opts ...RuleOption) *Rule {
	r, err := NewRule(opts...)
	Expect(err).NotTo(HaveOccurred())
	return r
}

func newTable(name string, order uint64, defaultAction Action) *Table {
	tbl, err := NewTable(name, order, defaultAction)
	Expect(err).NotTo(HaveOccurred())
	return tbl
}

func newChain(name string) *Chain {
	c, err := NewChain(name)
	Expect(err).NotTo(HaveOccurred())
	return c
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

	first := newTable("first", 1, Drop)
	second := newTable("second", 2, Drop)
	engine := New()

	Expect(engine.AddTable(first)).To(Succeed())
	Expect(engine.AddTable(second)).To(Succeed())

	Expect(engine.Tables).To(Equal([]*Table{first, second}))
}

func TestEvaluateSortsTablesByAscendingOrder(t *testing.T) {
	RegisterTestingT(t)

	acceptTable := newTable("accept-table", 2, Drop)
	acceptChain := newChain("default")
	Expect(acceptChain.AddRule(newRule(
		WithName("accept-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	))).To(Succeed())
	Expect(acceptTable.AddChain(acceptChain)).To(Succeed())

	passTable := newTable("pass-table", 1, Drop)
	passChain := newChain("default")
	Expect(passChain.AddRule(newRule(
		WithName("pass-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Pass),
	))).To(Succeed())
	Expect(passTable.AddChain(passChain)).To(Succeed())

	engine := New()
	Expect(engine.AddTable(acceptTable)).To(Succeed())
	Expect(engine.AddTable(passTable)).To(Succeed())

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	result, err := engine.Evaluate(pkt)

	Expect(err).NotTo(HaveOccurred())
	Expect(engine.Tables).To(Equal([]*Table{passTable, acceptTable}))
	Expect(result.Verdict).To(HaveValue(Equal(Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("pass-http"))
	Expect(result.Trace[1].Name).To(Equal("accept-http"))
}

func TestEvaluatePassesToNextTable(t *testing.T) {
	RegisterTestingT(t)

	passTable := newTable("pass-table", 1, Drop)
	passChain := newChain("default")
	Expect(passChain.AddRule(newRule(
		WithName("pass-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Pass),
	))).To(Succeed())
	Expect(passTable.AddChain(passChain)).To(Succeed())

	acceptTable := newTable("accept-table", 2, Drop)
	acceptChain := newChain("default")
	Expect(acceptChain.AddRule(newRule(
		WithName("accept-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	))).To(Succeed())
	Expect(acceptTable.AddChain(acceptChain)).To(Succeed())

	engine := New()
	Expect(engine.AddTable(passTable)).To(Succeed())
	Expect(engine.AddTable(acceptTable)).To(Succeed())

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	result, err := engine.Evaluate(pkt)

	Expect(err).NotTo(HaveOccurred())
	Expect(result.Verdict).To(HaveValue(Equal(Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("pass-http"))
	Expect(result.Trace[1].Name).To(Equal("accept-http"))
}

func TestEvaluateTracksEstablishedFlows(t *testing.T) {
	RegisterTestingT(t)

	stateful := newTable("stateful", 1, Drop)
	defaultChain := newChain("default")
	Expect(defaultChain.AddRule(newRule(
		WithName("allow-new-http"),
		WithConnState(conntrack.StateNew),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	))).To(Succeed())
	Expect(defaultChain.AddRule(newRule(
		WithName("allow-established"),
		WithConnState(conntrack.StateEstablished),
		WithProto(proto.TCP),
		WithAction(Accept),
	))).To(Succeed())
	Expect(stateful.AddChain(defaultChain)).To(Succeed())

	request := mustNewPacket(t,
		packet.WithName("request"),
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	reply := mustNewPacket(t,
		packet.WithName("reply"),
		packet.WithSrcAddr("1.1.1.1"),
		packet.WithDstAddr("10.0.0.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(80),
		packet.WithDstPort(12345),
	)

	engine := New(WithConntrack())
	Expect(engine.AddTable(stateful)).To(Succeed())

	requestResult, err := engine.Evaluate(request)
	Expect(err).NotTo(HaveOccurred())
	replyResult, err := engine.Evaluate(reply)

	Expect(err).NotTo(HaveOccurred())
	Expect(requestResult.ConnState).To(HaveValue(Equal(conntrack.StateNew)))
	expectMatchResult(requestResult, Accept, "allow-new-http")
	Expect(replyResult.ConnState).To(HaveValue(Equal(conntrack.StateEstablished)))
	expectMatchResult(replyResult, Accept, "allow-established")
}

func TestEvaluateWithoutConntrackDisablesStatefulMatching(t *testing.T) {
	RegisterTestingT(t)

	stateful := newTable("stateful", 1, Drop)
	defaultChain := newChain("default")
	Expect(defaultChain.AddRule(newRule(
		WithName("allow-new-http"),
		WithConnState(conntrack.StateNew),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	))).To(Succeed())
	Expect(defaultChain.AddRule(newRule(
		WithName("allow-established"),
		WithConnState(conntrack.StateEstablished),
		WithProto(proto.TCP),
		WithAction(Accept),
	))).To(Succeed())
	Expect(stateful.AddChain(defaultChain)).To(Succeed())

	request := mustNewPacket(t,
		packet.WithName("request"),
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	reply := mustNewPacket(t,
		packet.WithName("reply"),
		packet.WithSrcAddr("1.1.1.1"),
		packet.WithDstAddr("10.0.0.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(80),
		packet.WithDstPort(12345),
	)

	engine := New()
	Expect(engine.AddTable(stateful)).To(Succeed())

	requestResult, err := engine.Evaluate(request)
	Expect(err).NotTo(HaveOccurred())
	replyResult, err := engine.Evaluate(reply)

	Expect(err).NotTo(HaveOccurred())
	Expect(requestResult.ConnState).To(BeNil())
	expectMatchResult(requestResult, Accept, "allow-new-http")
	Expect(replyResult.ConnState).To(BeNil())
	expectMatchResult(replyResult, Drop, "table stateful default action")
}

func TestEvaluateSupportsJumpChains(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("main", 1, Drop)
	entry := newChain("entry")
	Expect(entry.AddRule(newRule(
		WithName("jump-admin"),
		WithSrcNet("10.0.0.0/8"),
		WithJump("admin"),
	))).To(Succeed())
	Expect(entry.AddRule(newRule(
		WithName("deny-all"),
		WithAction(Drop),
	))).To(Succeed())
	admin := newChain("admin")
	Expect(admin.AddRule(newRule(
		WithName("allow-admin-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	))).To(Succeed())
	Expect(tbl.AddChain(entry)).To(Succeed())
	Expect(tbl.AddChain(admin)).To(Succeed())
	Expect(tbl.SetEntryChain("entry")).To(Succeed())

	engine := New()
	Expect(engine.AddTable(tbl)).To(Succeed())

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	result, err := engine.Evaluate(pkt)

	Expect(err).NotTo(HaveOccurred())
	Expect(result.Verdict).To(HaveValue(Equal(Accept)))
	Expect(result.Trace).To(HaveLen(2))
	Expect(result.Trace[0].Name).To(Equal("jump-admin"))
	Expect(result.Trace[1].Name).To(Equal("allow-admin-http"))
}

func TestEvaluateReturnsErrorForMissingJumpTarget(t *testing.T) {
	RegisterTestingT(t)

	tbl := newTable("main", 1, Drop)
	entry := newChain("entry")
	Expect(entry.AddRule(newRule(
		WithName("jump-missing"),
		WithJump("missing"),
	))).To(Succeed())
	Expect(tbl.AddChain(entry)).To(Succeed())
	Expect(tbl.SetEntryChain("entry")).To(Succeed())

	engine := New()
	Expect(engine.AddTable(tbl)).To(Succeed())

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)
	result, err := engine.Evaluate(pkt)

	Expect(err).To(MatchError(`evaluate in table "main": chain "missing" not found`))
	Expect(result).To(BeNil())
}
