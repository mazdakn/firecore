package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/eval"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
	. "github.com/onsi/gomega"
)

func expectMatchResult(result *eval.Result, expectedVerdict rule.Action, expectedRule string) {
	Expect(result.Verdict).To(HaveValue(Equal(expectedVerdict)))
	Expect(result.Trace).NotTo(BeEmpty())
	Expect(result.Trace[len(result.Trace)-1].Name).To(Equal(expectedRule))
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

	first := table.New("first", 1, rule.Drop)
	second := table.New("second", 2, rule.Drop)
	engine := New()

	engine.AddTable(first)
	engine.AddTable(second)

	Expect(engine.Tables).To(Equal([]*table.Table{first, second}))
}

func TestEvaluateSortsTablesByAscendingOrder(t *testing.T) {
	RegisterTestingT(t)

	acceptTable := table.New("accept-table", 2, rule.Drop)
	acceptChain := table.NewChain("default")
	acceptChain.AddRule(rule.New(
		rule.WithName("accept-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	acceptTable.AddChain(acceptChain)

	passTable := table.New("pass-table", 1, rule.Drop)
	passChain := table.NewChain("default")
	passChain.AddRule(rule.New(
		rule.WithName("pass-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Pass),
	))
	passTable.AddChain(passChain)

	engine := New()
	engine.AddTable(acceptTable)
	engine.AddTable(passTable)

	results := engine.Evaluate([]*eval.Context{
		eval.New(packet.New(
			packet.WithSrcAddr("10.0.0.1"),
			packet.WithDstAddr("1.1.1.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(12345),
			packet.WithDstPort(80),
		)),
	})

	Expect(engine.Tables).To(Equal([]*table.Table{passTable, acceptTable}))
	Expect(results).To(HaveLen(1))
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(results[0].Trace).To(HaveLen(2))
	Expect(results[0].Trace[0].Name).To(Equal("pass-http"))
	Expect(results[0].Trace[1].Name).To(Equal("accept-http"))
}

func TestEvaluatePassesToNextTable(t *testing.T) {
	RegisterTestingT(t)

	passTable := table.New("pass-table", 1, rule.Drop)
	passChain := table.NewChain("default")
	passChain.AddRule(rule.New(
		rule.WithName("pass-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Pass),
	))
	passTable.AddChain(passChain)

	acceptTable := table.New("accept-table", 2, rule.Drop)
	acceptChain := table.NewChain("default")
	acceptChain.AddRule(rule.New(
		rule.WithName("accept-http"),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	acceptTable.AddChain(acceptChain)

	engine := New()
	engine.AddTable(passTable)
	engine.AddTable(acceptTable)

	results := engine.Evaluate([]*eval.Context{
		eval.New(packet.New(
			packet.WithSrcAddr("10.0.0.1"),
			packet.WithDstAddr("1.1.1.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(12345),
			packet.WithDstPort(80),
		)),
	})

	Expect(results).To(HaveLen(1))
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(results[0].Trace).To(HaveLen(2))
	Expect(results[0].Trace[0].Name).To(Equal("pass-http"))
	Expect(results[0].Trace[1].Name).To(Equal("accept-http"))
}

func TestEvaluateTracksEstablishedFlows(t *testing.T) {
	RegisterTestingT(t)

	stateful := table.New("stateful", 1, rule.Drop)
	defaultChain := table.NewChain("default")
	defaultChain.AddRule(rule.New(
		rule.WithName("allow-new-http"),
		rule.WithConnState(conntrack.StateNew),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	defaultChain.AddRule(rule.New(
		rule.WithName("allow-established"),
		rule.WithConnState(conntrack.StateEstablished),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	stateful.AddChain(defaultChain)

	request := eval.New(
		packet.New(
			packet.WithName("request"),
			packet.WithSrcAddr("10.0.0.1"),
			packet.WithDstAddr("1.1.1.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(12345),
			packet.WithDstPort(80),
		),
	)
	reply := eval.New(
		packet.New(
			packet.WithName("reply"),
			packet.WithSrcAddr("1.1.1.1"),
			packet.WithDstAddr("10.0.0.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(80),
			packet.WithDstPort(12345),
		),
	)

	engine := New(WithConntrack())
	engine.AddTable(stateful)

	results := engine.Evaluate([]*eval.Context{request, reply})

	Expect(results).To(HaveLen(2))
	Expect(request.ConnState).To(HaveValue(Equal(conntrack.StateNew)))
	expectMatchResult(results[0], rule.Accept, "allow-new-http")
	Expect(reply.ConnState).To(HaveValue(Equal(conntrack.StateEstablished)))
	expectMatchResult(results[1], rule.Accept, "allow-established")
}

func TestEvaluateWithoutConntrackDisablesStatefulMatching(t *testing.T) {
	RegisterTestingT(t)

	stateful := table.New("stateful", 1, rule.Drop)
	defaultChain := table.NewChain("default")
	defaultChain.AddRule(rule.New(
		rule.WithName("allow-new-http"),
		rule.WithConnState(conntrack.StateNew),
		rule.WithDstPort(80),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	defaultChain.AddRule(rule.New(
		rule.WithName("allow-established"),
		rule.WithConnState(conntrack.StateEstablished),
		rule.WithProto(proto.TCP),
		rule.WithAction(rule.Accept),
	))
	stateful.AddChain(defaultChain)

	request := eval.New(
		packet.New(
			packet.WithName("request"),
			packet.WithSrcAddr("10.0.0.1"),
			packet.WithDstAddr("1.1.1.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(12345),
			packet.WithDstPort(80),
		),
	)
	reply := eval.New(
		packet.New(
			packet.WithName("reply"),
			packet.WithSrcAddr("1.1.1.1"),
			packet.WithDstAddr("10.0.0.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(80),
			packet.WithDstPort(12345),
		),
	)

	engine := New()
	engine.AddTable(stateful)

	results := engine.Evaluate([]*eval.Context{request, reply})

	Expect(results).To(HaveLen(2))
	Expect(request.ConnState).To(BeNil())
	expectMatchResult(results[0], rule.Accept, "allow-new-http")
	Expect(reply.ConnState).To(BeNil())
	expectMatchResult(results[1], rule.Drop, "table stateful default action")
}

func TestEvaluateSupportsJumpChains(t *testing.T) {
	RegisterTestingT(t)

	tbl := table.New("main", 1, rule.Drop)
	entry := table.NewChain("entry")
	entry.AddRule(rule.New(
		rule.WithName("jump-admin"),
		rule.WithSrcNet("10.0.0.0/8"),
		rule.WithJump("admin"),
	))
	entry.AddRule(rule.New(
		rule.WithName("deny-all"),
		rule.WithAction(rule.Drop),
	))
	admin := table.NewChain("admin")
	admin.AddRule(rule.New(
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

	results := engine.Evaluate([]*eval.Context{
		eval.New(packet.New(
			packet.WithSrcAddr("10.0.0.1"),
			packet.WithDstAddr("1.1.1.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(12345),
			packet.WithDstPort(80),
		)),
	})

	Expect(results).To(HaveLen(1))
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(results[0].Trace).To(HaveLen(2))
	Expect(results[0].Trace[0].Name).To(Equal("jump-admin"))
	Expect(results[0].Trace[1].Name).To(Equal("allow-admin-http"))
}
