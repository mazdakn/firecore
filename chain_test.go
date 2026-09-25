package firecore

import (
	"strings"
	"testing"

	"github.com/mazdakn/firecore/packet"
)

func TestNewChainEmptyNameFails(t *testing.T) {
	chain, err := NewChain("")
	if err == nil {
		t.Fatal("NewChain(\"\") expected error, got nil")
	}
	if chain != nil {
		t.Errorf("NewChain(\"\") expected nil chain, got %v", chain)
	}
}

func TestChainAddRuleSortAscending(t *testing.T) {
	chain := newChain("main")

	rule1 := newRule(WithName("rule1"), WithOrder(10), WithAction(Accept))
	rule2 := newRule(WithName("rule2"), WithOrder(30), WithAction(Accept))
	rule3 := newRule(WithName("rule3"), WithOrder(20), WithAction(Accept))

	if err := chain.AddRule(rule1); err != nil {
		t.Fatalf("AddRule(rule1) unexpected error: %v", err)
	}
	if err := chain.AddRule(rule2); err != nil {
		t.Fatalf("AddRule(rule2) unexpected error: %v", err)
	}
	if err := chain.AddRule(rule3); err != nil {
		t.Fatalf("AddRule(rule3) unexpected error: %v", err)
	}

	if len(chain.Rules) != 3 {
		t.Fatalf("len(chain.Rules) = %d; want 3", len(chain.Rules))
	}
	if chain.Rules[0].Order != 10 {
		t.Errorf("chain.Rules[0].Order = %d; want 10", chain.Rules[0].Order)
	}
	if chain.Rules[1].Order != 20 {
		t.Errorf("chain.Rules[1].Order = %d; want 20", chain.Rules[1].Order)
	}
	if chain.Rules[2].Order != 30 {
		t.Errorf("chain.Rules[2].Order = %d; want 30", chain.Rules[2].Order)
	}
}

func TestChainAddRuleSortStableForEqualOrders(t *testing.T) {
	chain := newChain("main")

	rule1 := newRule(WithName("rule1"), WithAction(Accept))
	rule2 := newRule(WithName("rule2"), WithAction(Drop))
	rule3 := newRule(WithName("rule3"), WithAction(Accept))

	if err := chain.AddRule(rule1); err != nil {
		t.Fatalf("AddRule(rule1) unexpected error: %v", err)
	}
	if err := chain.AddRule(rule2); err != nil {
		t.Fatalf("AddRule(rule2) unexpected error: %v", err)
	}
	if err := chain.AddRule(rule3); err != nil {
		t.Fatalf("AddRule(rule3) unexpected error: %v", err)
	}

	if len(chain.Rules) != 3 {
		t.Fatalf("len(chain.Rules) = %d; want 3", len(chain.Rules))
	}
	if chain.Rules[0].Name != "rule1" {
		t.Errorf("chain.Rules[0].Name = %q; want rule1", chain.Rules[0].Name)
	}
	if chain.Rules[1].Name != "rule2" {
		t.Errorf("chain.Rules[1].Name = %q; want rule2", chain.Rules[1].Name)
	}
	if chain.Rules[2].Name != "rule3" {
		t.Errorf("chain.Rules[2].Name = %q; want rule3", chain.Rules[2].Name)
	}
}

func TestChainAddRuleNilFails(t *testing.T) {
	chain := newChain("main")
	if err := chain.AddRule(nil); err == nil {
		t.Fatal("AddRule(nil) expected error, got nil")
	}
}

func TestChainAddRuleDuplicateNameFails(t *testing.T) {
	chain := newChain("main")
	rule1 := newRule(WithName("dup"), WithAction(Accept))
	rule2 := newRule(WithName("dup"), WithAction(Drop))

	if err := chain.AddRule(rule1); err != nil {
		t.Fatalf("AddRule(rule1) unexpected error: %v", err)
	}
	if err := chain.AddRule(rule2); err == nil {
		t.Fatal("AddRule(rule2) expected error for duplicate name, got nil")
	}
	if len(chain.Rules) != 1 {
		t.Errorf("len(chain.Rules) = %d; want 1", len(chain.Rules))
	}
}

func TestChainAddRuleAllowsRepeatedAnonymousRules(t *testing.T) {
	chain := newChain("main")
	rule1 := newRule(WithAction(Accept))
	rule2 := newRule(WithAction(Drop))

	if err := chain.AddRule(rule1); err != nil {
		t.Fatalf("AddRule(rule1) unexpected error: %v", err)
	}
	if err := chain.AddRule(rule2); err != nil {
		t.Fatalf("AddRule(rule2) unexpected error: %v", err)
	}
	if len(chain.Rules) != 2 {
		t.Errorf("len(chain.Rules) = %d; want 2", len(chain.Rules))
	}
}

func TestTableJumpToChainAndReturn(t *testing.T) {
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
	if err := helperChain.AddRule(acceptHTTP); err != nil {
		t.Fatalf("AddRule(acceptHTTP) unexpected error: %v", err)
	}

	// entry chain: jump to helper for TCP traffic
	mainChain := newChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	if err := mainChain.AddRule(jumpRule); err != nil {
		t.Fatalf("AddRule(jumpRule) unexpected error: %v", err)
	}

	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain(mainChain) unexpected error: %v", err)
	}
	if err := tbl.AddChain(helperChain); err != nil {
		t.Fatalf("AddChain(helperChain) unexpected error: %v", err)
	}

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	if !matched {
		t.Errorf("tbl.Match() matched = false; want true")
	}
	if err != nil {
		t.Fatalf("tbl.Match() unexpected error: %v", err)
	}
	if result.Verdict == nil || *result.Verdict != Accept {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Accept)
	}
	if len(result.Trace) != 2 {
		t.Fatalf("len(result.Trace) = %d; want 2", len(result.Trace))
	}
	if result.Trace[0].Name != "jump-to-helper" {
		t.Errorf("result.Trace[0].Name = %q; want jump-to-helper", result.Trace[0].Name)
	}
	if result.Trace[1].Name != "accept-http" {
		t.Errorf("result.Trace[1].Name = %q; want accept-http", result.Trace[1].Name)
	}
}

func TestTableJumpChainNoMatchReturnsToCaller(t *testing.T) {
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
	if err := helperChain.AddRule(noMatchRule); err != nil {
		t.Fatalf("AddRule(noMatchRule) unexpected error: %v", err)
	}

	// entry chain: jump to helper, then fall through to default action
	mainChain := newChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	if err := mainChain.AddRule(jumpRule); err != nil {
		t.Fatalf("AddRule(jumpRule) unexpected error: %v", err)
	}

	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain(mainChain) unexpected error: %v", err)
	}
	if err := tbl.AddChain(helperChain); err != nil {
		t.Fatalf("AddChain(helperChain) unexpected error: %v", err)
	}

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	// helper chain returned, entry chain fell through → default Drop
	if err != nil {
		t.Fatalf("tbl.Match() unexpected error: %v", err)
	}
	if !matched {
		t.Errorf("tbl.Match() matched = false; want true")
	}
	if result.Verdict == nil || *result.Verdict != Drop {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Drop)
	}
}

func TestTableReturnActionReturnsToCallerChain(t *testing.T) {
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
	if err := helperChain.AddRule(returnRule); err != nil {
		t.Fatalf("AddRule(returnRule) unexpected error: %v", err)
	}

	// entry chain: jump to helper, then accept all
	mainChain := newChain("main")
	jumpRule := newRule(WithName("jump-to-helper"), WithOrder(1),
		WithJump("helper"), WithProto(6))
	acceptAll := newRule(WithName("accept-all"), WithOrder(2), WithAction(Accept))
	if err := mainChain.AddRule(jumpRule); err != nil {
		t.Fatalf("AddRule(jumpRule) unexpected error: %v", err)
	}
	if err := mainChain.AddRule(acceptAll); err != nil {
		t.Fatalf("AddRule(acceptAll) unexpected error: %v", err)
	}

	if err := tbl.AddChain(mainChain); err != nil {
		t.Fatalf("AddChain(mainChain) unexpected error: %v", err)
	}
	if err := tbl.AddChain(helperChain); err != nil {
		t.Fatalf("AddChain(helperChain) unexpected error: %v", err)
	}

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	// Return in helper → continues in main after jump-to-helper → accept-all
	if err != nil {
		t.Fatalf("tbl.Match() unexpected error: %v", err)
	}
	if !matched {
		t.Errorf("tbl.Match() matched = false; want true")
	}
	if result.Verdict == nil || *result.Verdict != Accept {
		t.Errorf("result.Verdict = %v; want %v", result.Verdict, Accept)
	}
	if len(result.Trace) == 0 || result.Trace[len(result.Trace)-1].Name != "accept-all" {
		t.Errorf("expected last trace rule name to be accept-all, got %v", result.Trace)
	}
}

func TestTableMatchReturnsErrorForMissingJumpTarget(t *testing.T) {
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

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)

	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	wantErr := `chain "missing" not found`
	if err == nil || err.Error() != wantErr {
		t.Errorf("err = %v; want %q", err, wantErr)
	}
	if matched {
		t.Errorf("tbl.Match() matched = true; want false")
	}
	if len(result.Trace) != 1 {
		t.Fatalf("len(result.Trace) = %d; want 1", len(result.Trace))
	}
	if result.Trace[0].Name != "jump-missing" {
		t.Errorf("result.Trace[0].Name = %q; want jump-missing", result.Trace[0].Name)
	}
}

func TestTableMatchReturnsErrorWhenJumpDepthExceeded(t *testing.T) {
	tbl := newTable("test", 0, Drop)

	// A direct cycle that Validate was not called to catch; Match must fail
	// safe via the depth limit instead of recursing until a stack overflow.
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

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithDstAddr("1.1.1.1"),
	)
	result := &Result{}
	matched, err := tbl.Match(pkt, result)

	if matched {
		t.Errorf("tbl.Match() matched = true; want false")
	}
	if err == nil || !strings.Contains(err.Error(), "jump depth exceeded") {
		t.Errorf("err = %v; want substring 'jump depth exceeded'", err)
	}
}
