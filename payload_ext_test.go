package firecore_test

import (
	"testing"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
)

func TestPayloadRegexPolicy(t *testing.T) {
	accept := mustParseAction(t, "accept")
	tcp := mustParseProto(t, "tcp")

	policy, err := firecore.NewTable("payload-policy", 1, firecore.Drop)
	if err != nil {
		t.Fatalf("NewTable unexpected error: %v", err)
	}

	entry := newChain(t, "entry")

	allowAPIKey, err := firecore.NewRule(
		firecore.WithName("allow-api-key"),
		firecore.WithProto(tcp),
		firecore.WithDstPort(8443),
		firecore.WithPayload(`(?i)api_key=[A-Za-z0-9_-]+`),
		firecore.WithAction(accept),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	if err := entry.AddRule(allowAPIKey); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := policy.AddChain(entry); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := policy.SetEntryChain("entry"); err != nil {
		t.Fatalf("SetEntryChain unexpected error: %v", err)
	}

	engine := newEngine(t)
	if err := engine.AddTable(policy); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	allowed := mustNewPacket(t,
		packet.WithName("allowed-api-request"),
		packet.WithSrcAddr("192.0.2.10"),
		packet.WithDstAddr("198.51.100.25"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(54000),
		packet.WithDstPort(8443),
		packet.WithPayload([]byte("GET /v1/data?api_key=test-123 HTTP/1.1")),
	)

	blocked := mustNewPacket(t,
		packet.WithName("blocked-api-request"),
		packet.WithSrcAddr("192.0.2.11"),
		packet.WithDstAddr("198.51.100.25"),
		packet.WithProto(proto.TCP),
		packet.WithSrcPort(54001),
		packet.WithDstPort(8443),
		packet.WithPayload([]byte("GET /v1/data HTTP/1.1")),
	)

	allowedResult, err := engine.Evaluate(allowed)
	if err != nil {
		t.Fatalf("Evaluate(allowed) unexpected error: %v", err)
	}
	blockedResult, err := engine.Evaluate(blocked)
	if err != nil {
		t.Fatalf("Evaluate(blocked) unexpected error: %v", err)
	}

	expectMatchResult(t, allowedResult, accept, "allow-api-key")
	if len(allowedResult.Trace) != 1 {
		t.Fatalf("len(allowedResult.Trace) = %d; want 1", len(allowedResult.Trace))
	}
	if allowedResult.Trace[0].Name != "allow-api-key" {
		t.Errorf("allowedResult.Trace[0].Name = %q; want allow-api-key", allowedResult.Trace[0].Name)
	}

	expectMatchResult(t, blockedResult, firecore.Drop, "table payload-policy default action")
	if len(blockedResult.Trace) != 2 {
		t.Fatalf("len(blockedResult.Trace) = %d; want 2", len(blockedResult.Trace))
	}
	if blockedResult.Trace[1].Name != "table payload-policy default action" {
		t.Errorf("blockedResult.Trace[1].Name = %q; want 'table payload-policy default action'", blockedResult.Trace[1].Name)
	}

	if got := allowAPIKey.PacketCount(); got != 1 {
		t.Errorf("allowAPIKey.PacketCount() = %d; want 1", got)
	}
	if got := policy.DefaultRule.PacketCount(); got != 1 {
		t.Errorf("policy.DefaultRule.PacketCount() = %d; want 1", got)
	}
}
