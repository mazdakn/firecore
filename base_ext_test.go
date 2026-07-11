package firecore_test

import (
	"testing"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/eval"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/port"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/set"
	. "github.com/onsi/gomega"
)

func expectMatchResult(result *eval.Result, expectedVerdict rule.Action, expectedRule string) {
	Expect(result.Verdict).To(HaveValue(Equal(expectedVerdict)))
	Expect(result.Trace).NotTo(BeEmpty())
	Expect(result.Trace[len(result.Trace)-1].Name).To(Equal(expectedRule))
}

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

func TestStatefulPolicyAcrossPublicPackages(t *testing.T) {
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

	t1, err := firecore.NewTable("policy", 10, rule.Drop)
	Expect(err).NotTo(HaveOccurred())

	entry := firecore.NewChain("entry")
	admin := firecore.NewChain("admin")

	allowEstablished, err := rule.New(
		rule.WithName("allow-established"),
		rule.WithConnState(stateEstablished),
		rule.WithProto(tcp),
		rule.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	jumpAdmin, err := rule.New(
		rule.WithName("jump-admin"),
		rule.WithSrcIPSet(adminSources),
		rule.WithSrcIfaceSet(mgmtIfaces),
		rule.WithProto(tcp),
		rule.WithJump("admin"),
	)
	Expect(err).NotTo(HaveOccurred())

	allowDNS, err := rule.New(
		rule.WithName("allow-public-dns"),
		rule.WithDstIPPortSet(dnsTargets),
		rule.WithProto(udp),
		rule.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	allowAdminWeb, err := rule.New(
		rule.WithName("allow-admin-web"),
		rule.WithDstPortSet(webPorts),
		rule.WithProto(tcp),
		rule.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	entry.AddRule(allowEstablished)
	entry.AddRule(jumpAdmin)
	entry.AddRule(allowDNS)
	admin.AddRule(allowAdminWeb)

	t1.AddChain(entry)
	t1.AddChain(admin)
	t1.SetEntryChain("entry")

	engine := firecore.New(firecore.WithConntrack())
	engine.AddTable(t1)

	request := packet.New(
		packet.WithName("admin-request"),
		packet.WithSrcAddr("10.1.2.3"),
		packet.WithDstAddr("172.16.0.10"),
		packet.WithIngressIface("mgmt0"),
		packet.WithProto(tcp),
		packet.WithSrcPort(42424),
		packet.WithDstPort(https.Resolve()),
	)
	reply := packet.New(
		packet.WithName("admin-reply"),
		packet.WithSrcAddr("172.16.0.10"),
		packet.WithDstAddr("10.1.2.3"),
		packet.WithEgressIface("mgmt0"),
		packet.WithProto(tcp),
		packet.WithSrcPort(https.Resolve()),
		packet.WithDstPort(42424),
	)
	dnsQuery := packet.New(
		packet.WithName("dns-query"),
		packet.WithSrcAddr("192.0.2.10"),
		packet.WithDstAddr("8.8.8.8"),
		packet.WithProto(udp),
		packet.WithSrcPort(53000),
		packet.WithDstPort(53),
	)
	outsider := packet.New(
		packet.WithName("outsider"),
		packet.WithSrcAddr("192.0.2.11"),
		packet.WithDstAddr("172.16.0.10"),
		packet.WithIngressIface("eth0"),
		packet.WithProto(tcp),
		packet.WithSrcPort(41000),
		packet.WithDstPort(443),
	)

	requestResult, err := engine.Evaluate(request)
	Expect(err).NotTo(HaveOccurred())
	replyResult, err := engine.Evaluate(reply)
	Expect(err).NotTo(HaveOccurred())
	dnsQueryResult, err := engine.Evaluate(dnsQuery)
	Expect(err).NotTo(HaveOccurred())
	outsiderResult, err := engine.Evaluate(outsider)

	Expect(err).NotTo(HaveOccurred())
	Expect(requestResult.ConnState).To(HaveValue(Equal(conntrack.StateNew)))
	expectMatchResult(requestResult, accept, "allow-admin-web")
	Expect(requestResult.Trace).To(HaveLen(3))
	Expect(requestResult.Trace[0].Name).To(Equal("allow-established"))
	Expect(requestResult.Trace[1].Name).To(Equal("jump-admin"))
	Expect(requestResult.Trace[2].Name).To(Equal("allow-admin-web"))

	Expect(replyResult.ConnState).To(HaveValue(Equal(stateEstablished)))
	expectMatchResult(replyResult, accept, "allow-established")
	Expect(replyResult.Trace).To(HaveLen(1))
	Expect(replyResult.Trace[0].Name).To(Equal("allow-established"))

	Expect(dnsQueryResult.ConnState).To(HaveValue(Equal(conntrack.StateNew)))
	expectMatchResult(dnsQueryResult, accept, "allow-public-dns")
	Expect(dnsQueryResult.Trace).To(HaveLen(3))
	Expect(dnsQueryResult.Trace[2].Name).To(Equal("allow-public-dns"))

	expectMatchResult(outsiderResult, rule.Drop, "table policy default action")
	Expect(outsiderResult.Trace).To(HaveLen(4))
	Expect(outsiderResult.Trace[3].Name).To(Equal("table policy default action"))

	Expect(jumpAdmin.PacketCount()).To(Equal(uint64(1)))
	Expect(allowAdminWeb.PacketCount()).To(Equal(uint64(1)))
	Expect(allowEstablished.PacketCount()).To(Equal(uint64(1)))
	Expect(allowDNS.PacketCount()).To(Equal(uint64(1)))
	Expect(t1.DefaultRule.PacketCount()).To(Equal(uint64(1)))
}

func TestPassReturnAndOrderedTables(t *testing.T) {
	RegisterTestingT(t)

	pass := mustParseAction(t, "pass")
	accept := mustParseAction(t, "accept")
	tcp := mustParseProto(t, "tcp")
	appPort := mustParsePort(t, "8080")

	trustedSources := set.NewIPSet()
	mustAddToSet(t, trustedSources, "192.0.2.0/24")

	classify, err := firecore.NewTable("classify", 1, rule.Drop)
	Expect(err).NotTo(HaveOccurred())

	classifyEntry := firecore.NewChain("entry")
	classifyReview := firecore.NewChain("review")

	jumpReview, err := rule.New(
		rule.WithName("jump-review"),
		rule.WithJump("review"),
	)
	Expect(err).NotTo(HaveOccurred())

	returnToEntry, err := rule.New(
		rule.WithName("return-to-entry"),
		rule.WithAction(rule.Return),
	)
	Expect(err).NotTo(HaveOccurred())

	passTrusted, err := rule.New(
		rule.WithName("pass-trusted-app"),
		rule.WithSrcIPSet(trustedSources),
		rule.WithDstPort(appPort.Resolve()),
		rule.WithProto(tcp),
		rule.WithAction(pass),
	)
	Expect(err).NotTo(HaveOccurred())

	classifyEntry.AddRule(jumpReview)
	classifyEntry.AddRule(passTrusted)
	classifyReview.AddRule(returnToEntry)
	classify.AddChain(classifyEntry)
	classify.AddChain(classifyReview)
	classify.SetEntryChain("entry")

	policy, err := firecore.NewTable("policy", 2, rule.Drop)
	Expect(err).NotTo(HaveOccurred())

	policyEntry := firecore.NewChain("entry")
	Expect(err).NotTo(HaveOccurred())

	allowTrustedApp, err := rule.New(
		rule.WithName("allow-trusted-app"),
		rule.WithSrcIPSet(trustedSources),
		rule.WithDstPort(appPort.Resolve()),
		rule.WithProto(tcp),
		rule.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	policyEntry.AddRule(allowTrustedApp)
	policy.AddChain(policyEntry)
	policy.SetEntryChain("entry")

	engine := firecore.New()
	engine.AddTable(classify)
	engine.AddTable(policy)

	pkt := packet.New(
		packet.WithSrcAddr("192.0.2.25"),
		packet.WithDstAddr("198.51.100.10"),
		packet.WithProto(tcp),
		packet.WithSrcPort(45000),
		packet.WithDstPort(appPort.Resolve()),
	)

	result, err := engine.Evaluate(pkt)

	Expect(err).NotTo(HaveOccurred())
	expectMatchResult(result, accept, "allow-trusted-app")
	Expect(result.Trace).To(HaveLen(4))
	Expect(result.Trace[0].Name).To(Equal("jump-review"))
	Expect(result.Trace[1].Name).To(Equal("return-to-entry"))
	Expect(result.Trace[2].Name).To(Equal("pass-trusted-app"))
	Expect(result.Trace[3].Name).To(Equal("allow-trusted-app"))

	Expect(jumpReview.PacketCount()).To(Equal(uint64(1)))
	Expect(returnToEntry.PacketCount()).To(Equal(uint64(1)))
	Expect(passTrusted.PacketCount()).To(Equal(uint64(1)))
	Expect(allowTrustedApp.PacketCount()).To(Equal(uint64(1)))
	Expect(classify.DefaultRule.PacketCount()).To(Equal(uint64(0)))
	Expect(policy.DefaultRule.PacketCount()).To(Equal(uint64(0)))
}
