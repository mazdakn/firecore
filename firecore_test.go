package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	Expect(engine).ToNot(BeNil())
	Expect(engine.Tables).To(BeNil())
	Expect(engine.ConntrackEnabled).To(BeTrue())
}

func TestNewAppliesOptions(t *testing.T) {
	RegisterTestingT(t)

	tables := []*table.Table{table.New("filter", 1, rule.Drop)}
	engine := New(WithTables(tables), WithNoConnTrack())

	Expect(engine.Tables).To(Equal(tables))
	Expect(engine.ConntrackEnabled).To(BeFalse())
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

	results := New(WithTables([]*table.Table{passTable, acceptTable})).Evaluate([]*match.MatchContext{
		match.New(packet.New(
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

	request := match.New(
		packet.New(
			packet.WithName("request"),
			packet.WithSrcAddr("10.0.0.1"),
			packet.WithDstAddr("1.1.1.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(12345),
			packet.WithDstPort(80),
		),
		match.WithExpectedVerdict(rule.Accept),
		match.WithExpectedRule("allow-new-http"),
	)
	reply := match.New(
		packet.New(
			packet.WithName("reply"),
			packet.WithSrcAddr("1.1.1.1"),
			packet.WithDstAddr("10.0.0.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(80),
			packet.WithDstPort(12345),
		),
		match.WithExpectedVerdict(rule.Accept),
		match.WithExpectedRule("allow-established"),
	)

	results := New(WithTables([]*table.Table{stateful})).Evaluate([]*match.MatchContext{request, reply})

	Expect(results).To(HaveLen(2))
	Expect(results[0].ConnState).To(Equal(conntrack.StateNew))
	Expect(results[0].VerdictMatches()).To(BeTrue())
	Expect(results[0].RuleMatches()).To(BeTrue())
	Expect(results[1].ConnState).To(Equal(conntrack.StateEstablished))
	Expect(results[1].VerdictMatches()).To(BeTrue())
	Expect(results[1].RuleMatches()).To(BeTrue())
}

func TestEvaluateWithNoConnTrackDisablesStatefulMatching(t *testing.T) {
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

	request := match.New(
		packet.New(
			packet.WithName("request"),
			packet.WithSrcAddr("10.0.0.1"),
			packet.WithDstAddr("1.1.1.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(12345),
			packet.WithDstPort(80),
		),
		match.WithExpectedVerdict(rule.Accept),
		match.WithExpectedRule("allow-new-http"),
	)
	reply := match.New(
		packet.New(
			packet.WithName("reply"),
			packet.WithSrcAddr("1.1.1.1"),
			packet.WithDstAddr("10.0.0.1"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(80),
			packet.WithDstPort(12345),
		),
		match.WithExpectedVerdict(rule.Drop),
		match.WithExpectedRule("table stateful default action"),
	)

	results := New(WithTables([]*table.Table{stateful}), WithNoConnTrack()).Evaluate([]*match.MatchContext{request, reply})

	Expect(results).To(HaveLen(2))
	Expect(results[0].ConnState).To(Equal(conntrack.StateNew))
	Expect(results[0].VerdictMatches()).To(BeTrue())
	Expect(results[0].RuleMatches()).To(BeTrue())
	Expect(results[1].ConnState).To(Equal(conntrack.StateNew))
	Expect(results[1].VerdictMatches()).To(BeTrue())
	Expect(results[1].RuleMatches()).To(BeTrue())
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

	results := New(WithTables([]*table.Table{tbl})).Evaluate([]*match.MatchContext{
		match.New(packet.New(
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
