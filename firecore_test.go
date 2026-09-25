package firecore

import (
	"fmt"
	"slices"
	"testing"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
)

func expectMatchResult(t *testing.T, result *Result, expectedVerdict Action, expectedRule string) {
	t.Helper()
	if result.Verdict == nil {
		t.Fatalf("expected verdict %v, got nil", expectedVerdict)
	}
	if *result.Verdict != expectedVerdict {
		t.Errorf("expected verdict %v, got %v", expectedVerdict, *result.Verdict)
	}
	if len(result.Trace) == 0 {
		t.Fatal("expected non-empty trace")
	}
	if last := result.Trace[len(result.Trace)-1].Name; last != expectedRule {
		t.Errorf("expected last trace rule %q, got %q", expectedRule, last)
	}
}

func newRule(opts ...RuleOption) *Rule {
	r, err := NewRule(opts...)
	if err != nil {
		panic(fmt.Sprintf("NewRule: %v", err))
	}
	return r
}

func newTable(name string, order uint64, defaultAction Action) *Table {
	tbl, err := NewTable(name, order, defaultAction)
	if err != nil {
		panic(fmt.Sprintf("NewTable: %v", err))
	}
	return tbl
}

func newChain(name string) *Chain {
	c, err := NewChain(name)
	if err != nil {
		panic(fmt.Sprintf("NewChain: %v", err))
	}
	return c
}

func newEngine(opts ...Option) *Engine {
	e, err := New(opts...)
	if err != nil {
		panic(fmt.Sprintf("New: %v", err))
	}
	return e
}

func TestNew(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("New() returned nil engine")
	}
	if engine.Tables != nil {
		t.Errorf("engine.Tables = %v; want nil", engine.Tables)
	}
	if engine.tracker != nil {
		t.Errorf("engine.tracker = %v; want nil", engine.tracker)
	}
}

func TestNewAppliesOptions(t *testing.T) {
	engine, err := New(WithConntrack())
	if err != nil {
		t.Fatalf("New(WithConntrack()) unexpected error: %v", err)
	}
	if engine.Tables != nil {
		t.Errorf("engine.Tables = %v; want nil", engine.Tables)
	}
	if engine.tracker == nil {
		t.Errorf("engine.tracker = nil; want non-nil")
	}
}

func TestNewNilOptionFails(t *testing.T) {
	engine, err := New(nil)
	if err == nil {
		t.Fatal("New(nil) expected error, got nil")
	}
	if engine != nil {
		t.Errorf("New(nil) expected nil engine, got %v", engine)
	}
}

func TestAddTable(t *testing.T) {
	first := newTable("first", 1, Drop)
	second := newTable("second", 2, Drop)
	engine := newEngine()

	if err := engine.AddTable(first); err != nil {
		t.Fatalf("AddTable(first) unexpected error: %v", err)
	}
	if err := engine.AddTable(second); err != nil {
		t.Fatalf("AddTable(second) unexpected error: %v", err)
	}

	if !slices.Equal(engine.Tables, []*Table{first, second}) {
		t.Errorf("engine.Tables = %v; want [%v, %v]", engine.Tables, first, second)
	}
}

func TestEvaluateSortsTablesByAscendingOrder(t *testing.T) {
	acceptTable := newTable("accept-table", 2, Drop)
	acceptChain := newChain("default")
	if err := acceptChain.AddRule(newRule(
		WithName("accept-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := acceptTable.AddChain(acceptChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	passTable := newTable("pass-table", 1, Drop)
	passChain := newChain("default")
	if err := passChain.AddRule(newRule(
		WithName("pass-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Pass),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := passTable.AddChain(passChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	engine := newEngine()
	if err := engine.AddTable(acceptTable); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}
	if err := engine.AddTable(passTable); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	result, err := engine.Evaluate(pkt)

	if err != nil {
		t.Fatalf("engine.Evaluate unexpected error: %v", err)
	}
	if !slices.Equal(engine.Tables, []*Table{passTable, acceptTable}) {
		t.Errorf("engine.Tables = %v; want [%v, %v]", engine.Tables, passTable, acceptTable)
	}
	if result.Verdict == nil || *result.Verdict != Accept {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Accept)
	}
	if len(result.Trace) != 2 {
		t.Fatalf("len(result.Trace) = %d; want 2", len(result.Trace))
	}
	if result.Trace[0].Name != "pass-http" {
		t.Errorf("result.Trace[0].Name = %q; want pass-http", result.Trace[0].Name)
	}
	if result.Trace[1].Name != "accept-http" {
		t.Errorf("result.Trace[1].Name = %q; want accept-http", result.Trace[1].Name)
	}
}

func TestEvaluatePassesToNextTable(t *testing.T) {
	passTable := newTable("pass-table", 1, Drop)
	passChain := newChain("default")
	if err := passChain.AddRule(newRule(
		WithName("pass-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Pass),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := passTable.AddChain(passChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	acceptTable := newTable("accept-table", 2, Drop)
	acceptChain := newChain("default")
	if err := acceptChain.AddRule(newRule(
		WithName("accept-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := acceptTable.AddChain(acceptChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	engine := newEngine()
	if err := engine.AddTable(passTable); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}
	if err := engine.AddTable(acceptTable); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	result, err := engine.Evaluate(pkt)

	if err != nil {
		t.Fatalf("engine.Evaluate unexpected error: %v", err)
	}
	if result.Verdict == nil || *result.Verdict != Accept {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Accept)
	}
	if len(result.Trace) != 2 {
		t.Fatalf("len(result.Trace) = %d; want 2", len(result.Trace))
	}
	if result.Trace[0].Name != "pass-http" {
		t.Errorf("result.Trace[0].Name = %q; want pass-http", result.Trace[0].Name)
	}
	if result.Trace[1].Name != "accept-http" {
		t.Errorf("result.Trace[1].Name = %q; want accept-http", result.Trace[1].Name)
	}
}

func TestEvaluateTracksEstablishedFlows(t *testing.T) {
	stateful := newTable("stateful", 1, Drop)
	defaultChain := newChain("default")
	if err := defaultChain.AddRule(newRule(
		WithName("allow-new-http"),
		WithConnState(conntrack.StateNew),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := defaultChain.AddRule(newRule(
		WithName("allow-established"),
		WithConnState(conntrack.StateEstablished),
		WithProto(proto.TCP),
		WithAction(Accept),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := stateful.AddChain(defaultChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

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

	engine := newEngine(WithConntrack())
	if err := engine.AddTable(stateful); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	requestResult, err := engine.Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate(request) unexpected error: %v", err)
	}
	replyResult, err := engine.Evaluate(reply)
	if err != nil {
		t.Fatalf("Evaluate(reply) unexpected error: %v", err)
	}

	if requestResult.ConnState == nil || *requestResult.ConnState != conntrack.StateNew {
		t.Errorf("requestResult.ConnState = %v; want %v", requestResult.ConnState, conntrack.StateNew)
	}
	expectMatchResult(t, requestResult, Accept, "allow-new-http")

	if replyResult.ConnState == nil || *replyResult.ConnState != conntrack.StateEstablished {
		t.Errorf("replyResult.ConnState = %v; want %v", replyResult.ConnState, conntrack.StateEstablished)
	}
	expectMatchResult(t, replyResult, Accept, "allow-established")
}

func TestEvaluateWithoutConntrackDisablesStatefulMatching(t *testing.T) {
	stateful := newTable("stateful", 1, Drop)
	defaultChain := newChain("default")
	if err := defaultChain.AddRule(newRule(
		WithName("allow-new-http"),
		WithConnState(conntrack.StateNew),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := defaultChain.AddRule(newRule(
		WithName("allow-established"),
		WithConnState(conntrack.StateEstablished),
		WithProto(proto.TCP),
		WithAction(Accept),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := stateful.AddChain(defaultChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

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

	engine := newEngine()
	if err := engine.AddTable(stateful); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	requestResult, err := engine.Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate(request) unexpected error: %v", err)
	}
	replyResult, err := engine.Evaluate(reply)
	if err != nil {
		t.Fatalf("Evaluate(reply) unexpected error: %v", err)
	}

	if requestResult.ConnState != nil {
		t.Errorf("requestResult.ConnState = %v; want nil", *requestResult.ConnState)
	}
	expectMatchResult(t, requestResult, Accept, "allow-new-http")

	if replyResult.ConnState != nil {
		t.Errorf("replyResult.ConnState = %v; want nil", *replyResult.ConnState)
	}
	expectMatchResult(t, replyResult, Drop, "table stateful default action")
}

func TestEvaluateSupportsJumpChains(t *testing.T) {
	tbl := newTable("main", 1, Drop)
	entry := newChain("entry")
	if err := entry.AddRule(newRule(
		WithName("jump-admin"),
		WithSrcNet("10.0.0.0/8"),
		WithJump("admin"),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := entry.AddRule(newRule(
		WithName("deny-all"),
		WithAction(Drop),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	admin := newChain("admin")
	if err := admin.AddRule(newRule(
		WithName("allow-admin-http"),
		WithDstPort(80),
		WithProto(proto.TCP),
		WithAction(Accept),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(entry); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := tbl.AddChain(admin); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := tbl.SetEntryChain("entry"); err != nil {
		t.Fatalf("SetEntryChain unexpected error: %v", err)
	}

	engine := newEngine()
	if err := engine.AddTable(tbl); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(12345),
		packet.WithDstPort(80),
	)
	result, err := engine.Evaluate(pkt)

	if err != nil {
		t.Fatalf("Evaluate unexpected error: %v", err)
	}
	if result.Verdict == nil || *result.Verdict != Accept {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Accept)
	}
	if len(result.Trace) != 2 {
		t.Fatalf("len(result.Trace) = %d; want 2", len(result.Trace))
	}
	if result.Trace[0].Name != "jump-admin" {
		t.Errorf("result.Trace[0].Name = %q; want jump-admin", result.Trace[0].Name)
	}
	if result.Trace[1].Name != "allow-admin-http" {
		t.Errorf("result.Trace[1].Name = %q; want allow-admin-http", result.Trace[1].Name)
	}
}

func TestEvaluateReturnsErrorForMissingJumpTarget(t *testing.T) {
	tbl := newTable("main", 1, Drop)
	entry := newChain("entry")
	if err := entry.AddRule(newRule(
		WithName("jump-missing"),
		WithJump("missing"),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(entry); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := tbl.SetEntryChain("entry"); err != nil {
		t.Fatalf("SetEntryChain unexpected error: %v", err)
	}

	engine := newEngine()
	if err := engine.AddTable(tbl); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)
	result, err := engine.Evaluate(pkt)

	wantErr := `evaluate in table "main": chain "missing" not found`
	if err == nil || err.Error() != wantErr {
		t.Errorf("err = %v; want %q", err, wantErr)
	}
	if result != nil {
		t.Errorf("result = %v; want nil", result)
	}
}
