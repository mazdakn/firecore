package tests

import (
	"testing"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/port"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/set"
	"github.com/mazdakn/firecore/table"
	. "github.com/onsi/gomega"
)

func mustParseAction(t *testing.T, raw string) rule.Action {
	t.Helper()

	action, err := rule.ParseAction(raw)
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

func TestFVStatefulPolicyAcrossPublicPackages(t *testing.T) {
	RegisterTestingT(t)

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

	policy := table.New("policy", 10, rule.Drop)
	entry := table.NewChain("entry")
	admin := table.NewChain("admin")

	allowEstablished := rule.New(
		rule.WithName("allow-established"),
		rule.WithConnState(stateEstablished),
		rule.WithProto(tcp),
		rule.WithAction(accept),
	)
	jumpAdmin := rule.New(
		rule.WithName("jump-admin"),
		rule.WithSrcIPSet(adminSources),
		rule.WithSrcIfaceSet(mgmtIfaces),
		rule.WithProto(tcp),
		rule.WithJump("admin"),
	)
	allowDNS := rule.New(
		rule.WithName("allow-public-dns"),
		rule.WithDstIPPortSet(dnsTargets),
		rule.WithProto(udp),
		rule.WithAction(accept),
	)
	allowAdminWeb := rule.New(
		rule.WithName("allow-admin-web"),
		rule.WithDstPortSet(webPorts),
		rule.WithProto(tcp),
		rule.WithAction(accept),
	)

	entry.AddRule(allowEstablished)
	entry.AddRule(jumpAdmin)
	entry.AddRule(allowDNS)
	admin.AddRule(allowAdminWeb)

	policy.AddChain(entry)
	policy.AddChain(admin)
	policy.SetEntryChain("entry")

	engine := firecore.New(firecore.WithTables([]*table.Table{policy}))

	request := match.New(
		packet.New(
			packet.WithName("admin-request"),
			packet.WithSrcAddr("10.1.2.3"),
			packet.WithDstAddr("172.16.0.10"),
			packet.WithIngressIface("mgmt0"),
			packet.WithProto(tcp),
			packet.WithSrcPort(42424),
			packet.WithDstPort(https.Resolve()),
		),
		match.WithExpectedVerdict(accept),
		match.WithExpectedRule("allow-admin-web"),
	)
	reply := match.New(
		packet.New(
			packet.WithName("admin-reply"),
			packet.WithSrcAddr("172.16.0.10"),
			packet.WithDstAddr("10.1.2.3"),
			packet.WithEgressIface("mgmt0"),
			packet.WithProto(tcp),
			packet.WithSrcPort(https.Resolve()),
			packet.WithDstPort(42424),
		),
		match.WithExpectedVerdict(accept),
		match.WithExpectedRule("allow-established"),
	)
	dnsQuery := match.New(
		packet.New(
			packet.WithName("dns-query"),
			packet.WithSrcAddr("192.0.2.10"),
			packet.WithDstAddr("8.8.8.8"),
			packet.WithProto(udp),
			packet.WithSrcPort(53000),
			packet.WithDstPort(53),
		),
		match.WithExpectedVerdict(accept),
		match.WithExpectedRule("allow-public-dns"),
	)
	outsider := match.New(
		packet.New(
			packet.WithName("outsider"),
			packet.WithSrcAddr("192.0.2.11"),
			packet.WithDstAddr("172.16.0.10"),
			packet.WithIngressIface("eth0"),
			packet.WithProto(tcp),
			packet.WithSrcPort(41000),
			packet.WithDstPort(443),
		),
		match.WithExpectedVerdict(rule.Drop),
		match.WithExpectedRule("table policy default action"),
	)

	results := engine.Evaluate([]*match.MatchContext{request, reply, dnsQuery, outsider})

	Expect(results).To(HaveLen(4))
	Expect(results[0].ConnState).To(Equal(conntrack.StateNew))
	Expect(results[0].VerdictMatches()).To(BeTrue())
	Expect(results[0].RuleMatches()).To(BeTrue())
	Expect(results[0].Trace).To(HaveLen(3))
	Expect(results[0].Trace[0].Name).To(Equal("allow-established"))
	Expect(results[0].Trace[1].Name).To(Equal("jump-admin"))
	Expect(results[0].Trace[2].Name).To(Equal("allow-admin-web"))

	Expect(results[1].ConnState).To(Equal(stateEstablished))
	Expect(results[1].VerdictMatches()).To(BeTrue())
	Expect(results[1].RuleMatches()).To(BeTrue())
	Expect(results[1].Trace).To(HaveLen(1))
	Expect(results[1].Trace[0].Name).To(Equal("allow-established"))

	Expect(results[2].ConnState).To(Equal(conntrack.StateNew))
	Expect(results[2].VerdictMatches()).To(BeTrue())
	Expect(results[2].RuleMatches()).To(BeTrue())
	Expect(results[2].Trace).To(HaveLen(3))
	Expect(results[2].Trace[2].Name).To(Equal("allow-public-dns"))

	Expect(results[3].VerdictMatches()).To(BeTrue())
	Expect(results[3].RuleMatches()).To(BeTrue())
	Expect(results[3].Trace).To(HaveLen(4))
	Expect(results[3].Trace[3].Name).To(Equal("table policy default action"))

	Expect(jumpAdmin.PacketCount()).To(Equal(uint64(1)))
	Expect(allowAdminWeb.PacketCount()).To(Equal(uint64(1)))
	Expect(allowEstablished.PacketCount()).To(Equal(uint64(1)))
	Expect(allowDNS.PacketCount()).To(Equal(uint64(1)))
	Expect(policy.DefaultRule.PacketCount()).To(Equal(uint64(1)))
}

func TestFVPassReturnAndOrderedTables(t *testing.T) {
	RegisterTestingT(t)

	pass := mustParseAction(t, "pass")
	accept := mustParseAction(t, "accept")
	tcp := mustParseProto(t, "tcp")
	appPort := mustParsePort(t, "8080")

	trustedSources := set.NewIPSet()
	mustAddToSet(t, trustedSources, "192.0.2.0/24")

	classify := table.New("classify", 1, rule.Drop)
	classifyEntry := table.NewChain("entry")
	classifyReview := table.NewChain("review")

	jumpReview := rule.New(
		rule.WithName("jump-review"),
		rule.WithJump("review"),
	)
	returnToEntry := rule.New(
		rule.WithName("return-to-entry"),
		rule.WithAction(rule.Return),
	)
	passTrusted := rule.New(
		rule.WithName("pass-trusted-app"),
		rule.WithSrcIPSet(trustedSources),
		rule.WithDstPort(appPort.Resolve()),
		rule.WithProto(tcp),
		rule.WithAction(pass),
	)

	classifyEntry.AddRule(jumpReview)
	classifyEntry.AddRule(passTrusted)
	classifyReview.AddRule(returnToEntry)
	classify.AddChain(classifyEntry)
	classify.AddChain(classifyReview)
	classify.SetEntryChain("entry")

	policy := table.New("policy", 2, rule.Drop)
	policyEntry := table.NewChain("entry")
	allowTrustedApp := rule.New(
		rule.WithName("allow-trusted-app"),
		rule.WithSrcIPSet(trustedSources),
		rule.WithDstPort(appPort.Resolve()),
		rule.WithProto(tcp),
		rule.WithAction(accept),
	)
	policyEntry.AddRule(allowTrustedApp)
	policy.AddChain(policyEntry)
	policy.SetEntryChain("entry")

	engine := firecore.New(firecore.WithTables([]*table.Table{classify, policy}))

	context := match.New(
		packet.New(
			packet.WithSrcAddr("192.0.2.25"),
			packet.WithDstAddr("198.51.100.10"),
			packet.WithProto(tcp),
			packet.WithSrcPort(45000),
			packet.WithDstPort(appPort.Resolve()),
		),
		match.WithExpectedVerdict(accept),
		match.WithExpectedRule("allow-trusted-app"),
	)

	results := engine.Evaluate([]*match.MatchContext{context})

	Expect(results).To(HaveLen(1))
	Expect(results[0].VerdictMatches()).To(BeTrue())
	Expect(results[0].RuleMatches()).To(BeTrue())
	Expect(results[0].Trace).To(HaveLen(4))
	Expect(results[0].Trace[0].Name).To(Equal("jump-review"))
	Expect(results[0].Trace[1].Name).To(Equal("return-to-entry"))
	Expect(results[0].Trace[2].Name).To(Equal("pass-trusted-app"))
	Expect(results[0].Trace[3].Name).To(Equal("allow-trusted-app"))

	Expect(jumpReview.PacketCount()).To(Equal(uint64(1)))
	Expect(returnToEntry.PacketCount()).To(Equal(uint64(1)))
	Expect(passTrusted.PacketCount()).To(Equal(uint64(1)))
	Expect(allowTrustedApp.PacketCount()).To(Equal(uint64(1)))
	Expect(classify.DefaultRule.PacketCount()).To(Equal(uint64(0)))
	Expect(policy.DefaultRule.PacketCount()).To(Equal(uint64(0)))
}
