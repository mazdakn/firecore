package firecore

import (
	"testing"

	"github.com/mazdakn/firecore/packet"
)

func TestNewTableEmptyNameFails(t *testing.T) {
	tbl, err := NewTable("", 0, Drop)
	if err == nil {
		t.Fatal("NewTable(\"\") expected error, got nil")
	}
	if tbl != nil {
		t.Errorf("NewTable(\"\") expected nil tbl, got %v", tbl)
	}
}

func TestAddChainNilFails(t *testing.T) {
	tbl := newTable("test", 0, Drop)
	if err := tbl.AddChain(nil); err == nil {
		t.Fatal("tbl.AddChain(nil) expected error, got nil")
	}
}

// TestAddChainEmptyNameFails constructs a Chain literal directly, bypassing
// NewChain's own empty-name check, to verify AddChain's defense-in-depth
// check still rejects it.
func TestAddChainEmptyNameFails(t *testing.T) {
	tbl := newTable("test", 0, Drop)
	if err := tbl.AddChain(&Chain{Name: ""}); err == nil {
		t.Fatal("tbl.AddChain(&Chain{Name: \"\"}) expected error, got nil")
	}
}

func TestAddChainDuplicateNameFails(t *testing.T) {
	tbl := newTable("test", 0, Drop)
	chain1, err := NewChain("main")
	if err != nil {
		t.Fatalf("NewChain(main) unexpected error: %v", err)
	}
	if err := tbl.AddChain(chain1); err != nil {
		t.Fatalf("tbl.AddChain(chain1) unexpected error: %v", err)
	}

	chain2, err := NewChain("main")
	if err != nil {
		t.Fatalf("NewChain(main) unexpected error: %v", err)
	}
	if err := tbl.AddChain(chain2); err == nil {
		t.Fatal("tbl.AddChain(chain2) expected error for duplicate name, got nil")
	}
}

func TestSetEntryChainUnknownNameFails(t *testing.T) {
	tbl := newTable("test", 0, Drop)
	if err := tbl.SetEntryChain("missing"); err == nil {
		t.Fatal("tbl.SetEntryChain(missing) expected error, got nil")
	}
	if got := tbl.EntryChain(); got != "" {
		t.Errorf("tbl.EntryChain() = %q; want empty string", got)
	}
}

func TestSetEntryChainKnownNameSucceeds(t *testing.T) {
	tbl := newTable("test", 0, Drop)
	if err := tbl.AddChain(newChain("main")); err != nil {
		t.Fatalf("tbl.AddChain(main) unexpected error: %v", err)
	}
	if err := tbl.AddChain(newChain("other")); err != nil {
		t.Fatalf("tbl.AddChain(other) unexpected error: %v", err)
	}

	if err := tbl.SetEntryChain("other"); err != nil {
		t.Fatalf("tbl.SetEntryChain(other) unexpected error: %v", err)
	}
	if got := tbl.EntryChain(); got != "other" {
		t.Errorf("tbl.EntryChain() = %q; want other", got)
	}
}

func TestSortTablesSortAscendingAndStable(t *testing.T) {
	t1 := newTable("first", 10, Accept)
	t2 := newTable("second", 0, Accept)
	t3 := newTable("third", 10, Accept)
	t4 := newTable("fourth", 5, Accept)

	tables := []*Table{t1, t2, t3, t4}
	SortTables(tables)

	if tables[0].Name != "second" {
		t.Errorf("tables[0].Name = %q; want second", tables[0].Name)
	}
	if tables[1].Name != "fourth" {
		t.Errorf("tables[1].Name = %q; want fourth", tables[1].Name)
	}
	if tables[2].Name != "first" {
		t.Errorf("tables[2].Name = %q; want first", tables[2].Name)
	}
	if tables[3].Name != "third" {
		t.Errorf("tables[3].Name = %q; want third", tables[3].Name)
	}
}

func TestTableMatchUsesAscendingOrder(t *testing.T) {
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

	if err := chain.AddRule(highOrderDrop); err != nil {
		t.Fatalf("AddRule(highOrderDrop) unexpected error: %v", err)
	}
	if err := chain.AddRule(lowOrderAccept); err != nil {
		t.Fatalf("AddRule(lowOrderAccept) unexpected error: %v", err)
	}
	if err := tbl.AddChain(chain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	result := &Result{}
	matched, err := tbl.Match(pkt, result)
	if err != nil {
		t.Fatalf("tbl.Match unexpected error: %v", err)
	}
	if !matched {
		t.Errorf("tbl.Match matched = false; want true")
	}
	if result.Verdict == nil || *result.Verdict != Accept {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Accept)
	}
}

func TestTableMatchPassRuleDoesNotEvaluateDefaultAction(t *testing.T) {
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

	if err := chain.AddRule(passRule); err != nil {
		t.Fatalf("AddRule(passRule) unexpected error: %v", err)
	}
	if err := tbl.AddChain(chain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	if err != nil {
		t.Fatalf("tbl.Match unexpected error: %v", err)
	}
	if matched {
		t.Errorf("tbl.Match matched = true; want false")
	}
	if result.Verdict == nil || *result.Verdict != Pass {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Pass)
	}
	if len(result.Trace) != 1 {
		t.Fatalf("len(result.Trace) = %d; want 1", len(result.Trace))
	}
	if result.Trace[0].Name != "pass-http" {
		t.Errorf("result.Trace[0].Name = %q; want pass-http", result.Trace[0].Name)
	}
}

func TestTableMatchNoRuleAndDefaultPassReturnsNoMatchVerdict(t *testing.T) {
	tbl := newTable("test", 0, Pass)
	chain := newChain("main")
	if err := tbl.AddChain(chain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	if err != nil {
		t.Fatalf("tbl.Match unexpected error: %v", err)
	}
	if matched {
		t.Errorf("tbl.Match matched = true; want false")
	}
	if result.Verdict != nil {
		t.Errorf("result.Verdict = %v; want nil", *result.Verdict)
	}
	if len(result.Trace) != 1 {
		t.Fatalf("len(result.Trace) = %d; want 1", len(result.Trace))
	}
	if result.Trace[0].Name != "table test default action" {
		t.Errorf("result.Trace[0].Name = %q; want 'table test default action'", result.Trace[0].Name)
	}
	if result.Trace[0].Action != Pass {
		t.Errorf("result.Trace[0].Action = %v; want Pass", result.Trace[0].Action)
	}
}

func TestTableMatchDefaultRuleTracksByteCount(t *testing.T) {
	tbl := newTable("test", 0, Pass)
	chain := newChain("main")
	if err := tbl.AddChain(chain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
		packet.WithPayload([]byte("hello")), packet.WithSize(74),
	)

	if got := tbl.DefaultRule.ByteCount(); got != 0 {
		t.Errorf("tbl.DefaultRule.ByteCount() = %d; want 0", got)
	}

	result := &Result{}
	_, err := tbl.Match(pkt, result)

	if err != nil {
		t.Fatalf("tbl.Match unexpected error: %v", err)
	}
	if got := tbl.DefaultRule.PacketCount(); got != 1 {
		t.Errorf("tbl.DefaultRule.PacketCount() = %d; want 1", got)
	}
	if got := tbl.DefaultRule.ByteCount(); got != 74 {
		t.Errorf("tbl.DefaultRule.ByteCount() = %d; want 74", got)
	}
}

func TestTableMatchNilDefaultRuleReturnsNoMatch(t *testing.T) {
	tbl := newTable("test", 0, Drop)
	tbl.DefaultRule = nil
	chain := newChain("main")
	if err := tbl.AddChain(chain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithProto(6),
		packet.WithDstPort(80),
	)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	if err != nil {
		t.Fatalf("tbl.Match unexpected error: %v", err)
	}
	if matched {
		t.Errorf("tbl.Match matched = true; want false")
	}
	if result.Verdict != nil {
		t.Errorf("result.Verdict = %v; want nil", *result.Verdict)
	}
	if len(result.Trace) != 0 {
		t.Errorf("len(result.Trace) = %d; want 0", len(result.Trace))
	}
}

func TestTableValidateReturnsErrorForMissingJumpTarget(t *testing.T) {
	tbl := newTable("test", 0, Drop)

	mainChain := newChain("main")
	if err := mainChain.AddRule(newRule(
		WithName("jump-missing"),
		WithJump("missing"),
	)); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	wantErr := `chain "main": rule "jump-missing" jumps to undefined chain "missing"`
	if err := tbl.Validate(); err == nil || err.Error() != wantErr {
		t.Errorf("tbl.Validate() = %v; want %q", err, wantErr)
	}
}

func TestTableValidateAllowsForwardReferencedChains(t *testing.T) {
	tbl := newTable("test", 0, Drop)

	// mainChain jumps to "helper" before helperChain has been created or
	// added to the table — this forward reference must remain valid.
	mainChain := newChain("main")
	if err := mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	wantErr := `chain "main": rule "jump-to-helper" jumps to undefined chain "helper"`
	if err := tbl.Validate(); err == nil || err.Error() != wantErr {
		t.Errorf("tbl.Validate() = %v; want %q", err, wantErr)
	}

	helperChain := newChain("helper")
	if err := helperChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(helperChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	if err := tbl.Validate(); err != nil {
		t.Errorf("tbl.Validate() unexpected error: %v", err)
	}
}

func TestTableValidateReturnsNilForNoJumpRules(t *testing.T) {
	tbl := newTable("test", 0, Drop)
	mainChain := newChain("main")
	if err := mainChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	if err := tbl.Validate(); err != nil {
		t.Errorf("tbl.Validate() unexpected error: %v", err)
	}
}

func TestTableValidateDetectsDirectCycle(t *testing.T) {
	tbl := newTable("test", 0, Drop)

	mainChain := newChain("main")
	if err := mainChain.AddRule(newRule(WithName("jump-to-helper"), WithJump("helper"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	helperChain := newChain("helper")
	if err := helperChain.AddRule(newRule(WithName("jump-to-main"), WithJump("main"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(helperChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	wantErr := `chain "main": rule "jump-to-helper" creates a jump cycle: helper -> main -> helper`
	if err := tbl.Validate(); err == nil || err.Error() != wantErr {
		t.Errorf("tbl.Validate() = %v; want %q", err, wantErr)
	}
}

func TestTableValidateDetectsSelfLoop(t *testing.T) {
	tbl := newTable("test", 0, Drop)

	mainChain := newChain("main")
	if err := mainChain.AddRule(newRule(WithName("jump-to-self"), WithJump("main"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	wantErr := `chain "main": rule "jump-to-self" creates a jump cycle: main -> main`
	if err := tbl.Validate(); err == nil || err.Error() != wantErr {
		t.Errorf("tbl.Validate() = %v; want %q", err, wantErr)
	}
}

func TestTableValidateAllowsDiamondJumps(t *testing.T) {
	tbl := newTable("test", 0, Drop)

	// main jumps to both left and right, which both jump to shared — not a
	// cycle, just two paths converging on the same chain.
	mainChain := newChain("main")
	if err := mainChain.AddRule(newRule(WithName("jump-left"), WithOrder(1), WithJump("left"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := mainChain.AddRule(newRule(WithName("jump-right"), WithOrder(2), WithJump("right"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	leftChain := newChain("left")
	if err := leftChain.AddRule(newRule(WithName("left-to-shared"), WithJump("shared"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(leftChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	rightChain := newChain("right")
	if err := rightChain.AddRule(newRule(WithName("right-to-shared"), WithJump("shared"))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(rightChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	sharedChain := newChain("shared")
	if err := sharedChain.AddRule(newRule(WithName("accept-all"), WithAction(Accept))); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := tbl.AddChain(sharedChain); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}

	if err := tbl.Validate(); err != nil {
		t.Errorf("tbl.Validate() unexpected error: %v", err)
	}
}
