package firecore_test

import (
	"testing"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/port"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/set"
)

func expectMatchResult(t *testing.T, result *firecore.Result, expectedVerdict firecore.Action, expectedRule string) {
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

func mustParseAction(t *testing.T, raw string) firecore.Action {
	t.Helper()

	action, err := firecore.ParseAction(raw)
	if err != nil {
		t.Fatalf("parse action %q: %v", raw, err)
	}
	return action
}

func mustParseProto(t *testing.T, raw string) proto.Proto {
	t.Helper()

	p, err := proto.Parse(raw)
	if err != nil {
		t.Fatalf("parse proto %q: %v", raw, err)
	}
	return *p
}

func mustParseConnState(t *testing.T, raw string) conntrack.State {
	t.Helper()

	state, err := conntrack.ParseState(raw)
	if err != nil {
		t.Fatalf("parse conntrack state %q: %v", raw, err)
	}
	return state
}

func mustParsePort(t *testing.T, raw string) port.Port {
	t.Helper()

	p, err := port.Parse(raw)
	if err != nil {
		t.Fatalf("parse port %q: %v", raw, err)
	}
	return *p
}

func mustAddToSet(t *testing.T, s set.Set, value any) {
	t.Helper()

	if err := s.Add(value); err != nil {
		t.Fatalf("add %v to set: %v", value, err)
	}
}

func mustNewPacket(t testing.TB, opts ...packet.Option) *packet.Packet {
	t.Helper()
	pkt, err := packet.New(opts...)
	if err != nil {
		t.Fatalf("packet.New: %v", err)
	}
	return pkt
}

func newChain(t testing.TB, name string) *firecore.Chain {
	t.Helper()
	c, err := firecore.NewChain(name)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	return c
}

func newEngine(t testing.TB, opts ...firecore.Option) *firecore.Engine {
	t.Helper()
	e, err := firecore.New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestStatefulPolicyAcrossPublicPackages(t *testing.T) {
	accept := mustParseAction(t, "accept")
	tcp := mustParseProto(t, "tcp")
	udp := mustParseProto(t, "udp")
	stateEstablished := mustParseConnState(t, "established")
	https := mustParsePort(t, "https")

	adminSources := set.NewIPSet()
	mustAddToSet(t, adminSources, "10.0.0.0/8")

	mgmtIfaces := set.NewIfaceSet()
	mustAddToSet(t, mgmtIfaces, "mgmt0")

	webPorts := set.NewPortSet()
	mustAddToSet(t, webPorts, "http")
	mustAddToSet(t, webPorts, https)

	dnsTargets := set.NewIPPortSet()
	mustAddToSet(t, dnsTargets, "8.8.8.8,53")

	t1, err := firecore.NewTable("policy", 10, firecore.Drop)
	if err != nil {
		t.Fatalf("NewTable unexpected error: %v", err)
	}

	entry := newChain(t, "entry")
	admin := newChain(t, "admin")

	allowEstablished, err := firecore.NewRule(
		firecore.WithName("allow-established"),
		firecore.WithConnState(stateEstablished),
		firecore.WithProto(tcp),
		firecore.WithAction(accept),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	jumpAdmin, err := firecore.NewRule(
		firecore.WithName("jump-admin"),
		firecore.WithSrcSet(adminSources),
		firecore.WithSrcSet(mgmtIfaces),
		firecore.WithProto(tcp),
		firecore.WithJump("admin"),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	allowDNS, err := firecore.NewRule(
		firecore.WithName("allow-public-dns"),
		firecore.WithDstSet(dnsTargets),
		firecore.WithProto(udp),
		firecore.WithAction(accept),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	allowAdminWeb, err := firecore.NewRule(
		firecore.WithName("allow-admin-web"),
		firecore.WithDstSet(webPorts),
		firecore.WithProto(tcp),
		firecore.WithAction(accept),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	if err := entry.AddRule(allowEstablished); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := entry.AddRule(jumpAdmin); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := entry.AddRule(allowDNS); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := admin.AddRule(allowAdminWeb); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}

	if err := t1.AddChain(entry); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := t1.AddChain(admin); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := t1.SetEntryChain("entry"); err != nil {
		t.Fatalf("SetEntryChain unexpected error: %v", err)
	}

	engine := newEngine(t, firecore.WithConntrack())
	if err := engine.AddTable(t1); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	request := mustNewPacket(t,
		packet.WithName("admin-request"),
		packet.WithSrcAddr("10.1.2.3"),
		packet.WithDstAddr("172.16.0.10"),
		packet.WithIngressIface("mgmt0"),
		packet.WithProto(tcp),
		packet.WithSrcPort(42424),
		packet.WithDstPort(https.Resolve()),
	)
	reply := mustNewPacket(t,
		packet.WithName("admin-reply"),
		packet.WithSrcAddr("172.16.0.10"),
		packet.WithDstAddr("10.1.2.3"),
		packet.WithEgressIface("mgmt0"),
		packet.WithProto(tcp),
		packet.WithSrcPort(https.Resolve()),
		packet.WithDstPort(42424),
	)
	dnsQuery := mustNewPacket(t,
		packet.WithName("dns-query"),
		packet.WithSrcAddr("192.0.2.10"),
		packet.WithDstAddr("8.8.8.8"),
		packet.WithProto(udp),
		packet.WithSrcPort(53000),
		packet.WithDstPort(53),
	)
	outsider := mustNewPacket(t,
		packet.WithName("outsider"),
		packet.WithSrcAddr("192.0.2.11"),
		packet.WithDstAddr("172.16.0.10"),
		packet.WithIngressIface("eth0"),
		packet.WithProto(tcp),
		packet.WithSrcPort(41000),
		packet.WithDstPort(443),
	)

	requestResult, err := engine.Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate(request) unexpected error: %v", err)
	}
	replyResult, err := engine.Evaluate(reply)
	if err != nil {
		t.Fatalf("Evaluate(reply) unexpected error: %v", err)
	}
	dnsQueryResult, err := engine.Evaluate(dnsQuery)
	if err != nil {
		t.Fatalf("Evaluate(dnsQuery) unexpected error: %v", err)
	}
	outsiderResult, err := engine.Evaluate(outsider)
	if err != nil {
		t.Fatalf("Evaluate(outsider) unexpected error: %v", err)
	}

	if requestResult.ConnState == nil || *requestResult.ConnState != conntrack.StateNew {
		t.Errorf("requestResult.ConnState = %v; want %v", requestResult.ConnState, conntrack.StateNew)
	}
	expectMatchResult(t, requestResult, accept, "allow-admin-web")
	if len(requestResult.Trace) != 3 {
		t.Fatalf("len(requestResult.Trace) = %d; want 3", len(requestResult.Trace))
	}
	if requestResult.Trace[0].Name != "allow-established" {
		t.Errorf("requestResult.Trace[0].Name = %q; want allow-established", requestResult.Trace[0].Name)
	}
	if requestResult.Trace[1].Name != "jump-admin" {
		t.Errorf("requestResult.Trace[1].Name = %q; want jump-admin", requestResult.Trace[1].Name)
	}
	if requestResult.Trace[2].Name != "allow-admin-web" {
		t.Errorf("requestResult.Trace[2].Name = %q; want allow-admin-web", requestResult.Trace[2].Name)
	}

	if replyResult.ConnState == nil || *replyResult.ConnState != stateEstablished {
		t.Errorf("replyResult.ConnState = %v; want %v", replyResult.ConnState, stateEstablished)
	}
	expectMatchResult(t, replyResult, accept, "allow-established")
	if len(replyResult.Trace) != 1 {
		t.Fatalf("len(replyResult.Trace) = %d; want 1", len(replyResult.Trace))
	}
	if replyResult.Trace[0].Name != "allow-established" {
		t.Errorf("replyResult.Trace[0].Name = %q; want allow-established", replyResult.Trace[0].Name)
	}

	if dnsQueryResult.ConnState == nil || *dnsQueryResult.ConnState != conntrack.StateNew {
		t.Errorf("dnsQueryResult.ConnState = %v; want %v", dnsQueryResult.ConnState, conntrack.StateNew)
	}
	expectMatchResult(t, dnsQueryResult, accept, "allow-public-dns")
	if len(dnsQueryResult.Trace) != 3 {
		t.Fatalf("len(dnsQueryResult.Trace) = %d; want 3", len(dnsQueryResult.Trace))
	}
	if dnsQueryResult.Trace[2].Name != "allow-public-dns" {
		t.Errorf("dnsQueryResult.Trace[2].Name = %q; want allow-public-dns", dnsQueryResult.Trace[2].Name)
	}

	expectMatchResult(t, outsiderResult, firecore.Drop, "table policy default action")
	if len(outsiderResult.Trace) != 4 {
		t.Fatalf("len(outsiderResult.Trace) = %d; want 4", len(outsiderResult.Trace))
	}
	if outsiderResult.Trace[3].Name != "table policy default action" {
		t.Errorf("outsiderResult.Trace[3].Name = %q; want 'table policy default action'", outsiderResult.Trace[3].Name)
	}

	if got := jumpAdmin.PacketCount(); got != 1 {
		t.Errorf("jumpAdmin.PacketCount() = %d; want 1", got)
	}
	if got := allowAdminWeb.PacketCount(); got != 1 {
		t.Errorf("allowAdminWeb.PacketCount() = %d; want 1", got)
	}
	if got := allowEstablished.PacketCount(); got != 1 {
		t.Errorf("allowEstablished.PacketCount() = %d; want 1", got)
	}
	if got := allowDNS.PacketCount(); got != 1 {
		t.Errorf("allowDNS.PacketCount() = %d; want 1", got)
	}
	if got := t1.DefaultRule.PacketCount(); got != 1 {
		t.Errorf("t1.DefaultRule.PacketCount() = %d; want 1", got)
	}
}

func TestPassReturnAndOrderedTables(t *testing.T) {
	pass := mustParseAction(t, "pass")
	accept := mustParseAction(t, "accept")
	tcp := mustParseProto(t, "tcp")
	appPort := mustParsePort(t, "8080")

	trustedSources := set.NewIPSet()
	mustAddToSet(t, trustedSources, "192.0.2.0/24")

	classify, err := firecore.NewTable("classify", 1, firecore.Drop)
	if err != nil {
		t.Fatalf("NewTable unexpected error: %v", err)
	}

	classifyEntry := newChain(t, "entry")
	classifyReview := newChain(t, "review")

	jumpReview, err := firecore.NewRule(
		firecore.WithName("jump-review"),
		firecore.WithJump("review"),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	returnToEntry, err := firecore.NewRule(
		firecore.WithName("return-to-entry"),
		firecore.WithAction(firecore.Return),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	passTrusted, err := firecore.NewRule(
		firecore.WithName("pass-trusted-app"),
		firecore.WithSrcSet(trustedSources),
		firecore.WithDstPort(appPort.Resolve()),
		firecore.WithProto(tcp),
		firecore.WithAction(pass),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	if err := classifyEntry.AddRule(jumpReview); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := classifyEntry.AddRule(passTrusted); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := classifyReview.AddRule(returnToEntry); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := classify.AddChain(classifyEntry); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := classify.AddChain(classifyReview); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := classify.SetEntryChain("entry"); err != nil {
		t.Fatalf("SetEntryChain unexpected error: %v", err)
	}

	policy, err := firecore.NewTable("policy", 2, firecore.Drop)
	if err != nil {
		t.Fatalf("NewTable unexpected error: %v", err)
	}

	policyEntry := newChain(t, "entry")

	allowTrustedApp, err := firecore.NewRule(
		firecore.WithName("allow-trusted-app"),
		firecore.WithSrcSet(trustedSources),
		firecore.WithDstPort(appPort.Resolve()),
		firecore.WithProto(tcp),
		firecore.WithAction(accept),
	)
	if err != nil {
		t.Fatalf("NewRule unexpected error: %v", err)
	}

	if err := policyEntry.AddRule(allowTrustedApp); err != nil {
		t.Fatalf("AddRule unexpected error: %v", err)
	}
	if err := policy.AddChain(policyEntry); err != nil {
		t.Fatalf("AddChain unexpected error: %v", err)
	}
	if err := policy.SetEntryChain("entry"); err != nil {
		t.Fatalf("SetEntryChain unexpected error: %v", err)
	}

	engine := newEngine(t)
	if err := engine.AddTable(classify); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}
	if err := engine.AddTable(policy); err != nil {
		t.Fatalf("AddTable unexpected error: %v", err)
	}

	pkt := mustNewPacket(t,
		packet.WithSrcAddr("192.0.2.25"),
		packet.WithDstAddr("198.51.100.10"),
		packet.WithProto(tcp),
		packet.WithSrcPort(45000),
		packet.WithDstPort(appPort.Resolve()),
	)

	result, err := engine.Evaluate(pkt)

	if err != nil {
		t.Fatalf("engine.Evaluate unexpected error: %v", err)
	}
	expectMatchResult(t, result, accept, "allow-trusted-app")
	if len(result.Trace) != 4 {
		t.Fatalf("len(result.Trace) = %d; want 4", len(result.Trace))
	}
	if result.Trace[0].Name != "jump-review" {
		t.Errorf("result.Trace[0].Name = %q; want jump-review", result.Trace[0].Name)
	}
	if result.Trace[1].Name != "return-to-entry" {
		t.Errorf("result.Trace[1].Name = %q; want return-to-entry", result.Trace[1].Name)
	}
	if result.Trace[2].Name != "pass-trusted-app" {
		t.Errorf("result.Trace[2].Name = %q; want pass-trusted-app", result.Trace[2].Name)
	}
	if result.Trace[3].Name != "allow-trusted-app" {
		t.Errorf("result.Trace[3].Name = %q; want allow-trusted-app", result.Trace[3].Name)
	}

	if got := jumpReview.PacketCount(); got != 1 {
		t.Errorf("jumpReview.PacketCount() = %d; want 1", got)
	}
	if got := returnToEntry.PacketCount(); got != 1 {
		t.Errorf("returnToEntry.PacketCount() = %d; want 1", got)
	}
	if got := passTrusted.PacketCount(); got != 1 {
		t.Errorf("passTrusted.PacketCount() = %d; want 1", got)
	}
	if got := allowTrustedApp.PacketCount(); got != 1 {
		t.Errorf("allowTrustedApp.PacketCount() = %d; want 1", got)
	}
	if got := classify.DefaultRule.PacketCount(); got != 0 {
		t.Errorf("classify.DefaultRule.PacketCount() = %d; want 0", got)
	}
	if got := policy.DefaultRule.PacketCount(); got != 0 {
		t.Errorf("policy.DefaultRule.PacketCount() = %d; want 0", got)
	}
}
