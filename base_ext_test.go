package firecore_test

import (
	"testing"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/port"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/set"
	. "github.com/onsi/gomega"
)

func expectMatchResult(result *firecore.Result, expectedVerdict firecore.Action, expectedRule string) {
	Expect(result.Verdict).To(HaveValue(Equal(expectedVerdict)))
	Expect(result.Trace).NotTo(BeEmpty())
	Expect(result.Trace[len(result.Trace)-1].Name).To(Equal(expectedRule))
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

func mustNewPacket(t testing.TB, opts ...packet.PacketOption) *packet.Packet {
	t.Helper()
	pkt, err := packet.New(opts...)
	Expect(err).ToNot(HaveOccurred())
	return pkt
}

func newChain(t testing.TB, name string) *firecore.Chain {
	t.Helper()
	c, err := firecore.NewChain(name)
	Expect(err).ToNot(HaveOccurred())
	return c
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

	t1, err := firecore.NewTable("policy", 10, firecore.Drop)
	Expect(err).NotTo(HaveOccurred())

	entry := newChain(t, "entry")
	admin := newChain(t, "admin")

	allowEstablished, err := firecore.NewRule(
		firecore.WithName("allow-established"),
		firecore.WithConnState(stateEstablished),
		firecore.WithProto(tcp),
		firecore.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	jumpAdmin, err := firecore.NewRule(
		firecore.WithName("jump-admin"),
		firecore.WithSrcSet(adminSources),
		firecore.WithSrcSet(mgmtIfaces),
		firecore.WithProto(tcp),
		firecore.WithJump("admin"),
	)
	Expect(err).NotTo(HaveOccurred())

	allowDNS, err := firecore.NewRule(
		firecore.WithName("allow-public-dns"),
		firecore.WithDstSet(dnsTargets),
		firecore.WithProto(udp),
		firecore.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	allowAdminWeb, err := firecore.NewRule(
		firecore.WithName("allow-admin-web"),
		firecore.WithDstSet(webPorts),
		firecore.WithProto(tcp),
		firecore.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	Expect(entry.AddRule(allowEstablished)).To(Succeed())
	Expect(entry.AddRule(jumpAdmin)).To(Succeed())
	Expect(entry.AddRule(allowDNS)).To(Succeed())
	Expect(admin.AddRule(allowAdminWeb)).To(Succeed())

	Expect(t1.AddChain(entry)).To(Succeed())
	Expect(t1.AddChain(admin)).To(Succeed())
	t1.SetEntryChain("entry")

	engine := firecore.New(firecore.WithConntrack())
	Expect(engine.AddTable(t1)).To(Succeed())

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

	expectMatchResult(outsiderResult, firecore.Drop, "table policy default action")
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

	classify, err := firecore.NewTable("classify", 1, firecore.Drop)
	Expect(err).NotTo(HaveOccurred())

	classifyEntry := newChain(t, "entry")
	classifyReview := newChain(t, "review")

	jumpReview, err := firecore.NewRule(
		firecore.WithName("jump-review"),
		firecore.WithJump("review"),
	)
	Expect(err).NotTo(HaveOccurred())

	returnToEntry, err := firecore.NewRule(
		firecore.WithName("return-to-entry"),
		firecore.WithAction(firecore.Return),
	)
	Expect(err).NotTo(HaveOccurred())

	passTrusted, err := firecore.NewRule(
		firecore.WithName("pass-trusted-app"),
		firecore.WithSrcSet(trustedSources),
		firecore.WithDstPort(appPort.Resolve()),
		firecore.WithProto(tcp),
		firecore.WithAction(pass),
	)
	Expect(err).NotTo(HaveOccurred())

	Expect(classifyEntry.AddRule(jumpReview)).To(Succeed())
	Expect(classifyEntry.AddRule(passTrusted)).To(Succeed())
	Expect(classifyReview.AddRule(returnToEntry)).To(Succeed())
	Expect(classify.AddChain(classifyEntry)).To(Succeed())
	Expect(classify.AddChain(classifyReview)).To(Succeed())
	classify.SetEntryChain("entry")

	policy, err := firecore.NewTable("policy", 2, firecore.Drop)
	Expect(err).NotTo(HaveOccurred())

	policyEntry := newChain(t, "entry")
	Expect(err).NotTo(HaveOccurred())

	allowTrustedApp, err := firecore.NewRule(
		firecore.WithName("allow-trusted-app"),
		firecore.WithSrcSet(trustedSources),
		firecore.WithDstPort(appPort.Resolve()),
		firecore.WithProto(tcp),
		firecore.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	Expect(policyEntry.AddRule(allowTrustedApp)).To(Succeed())
	Expect(policy.AddChain(policyEntry)).To(Succeed())
	policy.SetEntryChain("entry")

	engine := firecore.New()
	Expect(engine.AddTable(classify)).To(Succeed())
	Expect(engine.AddTable(policy)).To(Succeed())

	pkt := mustNewPacket(t,
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
