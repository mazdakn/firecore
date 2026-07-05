package tests

import (
	"testing"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
	. "github.com/onsi/gomega"
)

func TestFVPayloadRegexPolicy(t *testing.T) {
	RegisterTestingT(t)

	accept := mustParseAction(t, "accept")
	tcp := mustParseProto(t, "tcp")

	policy := table.New("payload-policy", 1, rule.Drop)
	entry := table.NewChain("entry")

	allowAPIKey := rule.New(
		rule.WithName("allow-api-key"),
		rule.WithProto(tcp),
		rule.WithDstPort(8443),
		rule.WithPayload(`(?i)api_key=[A-Za-z0-9_-]+`),
		rule.WithAction(accept),
	)

	entry.AddRule(allowAPIKey)
	policy.AddChain(entry)
	policy.SetEntryChain("entry")

	engine := firecore.New()
	engine.AddTable(policy)

	allowed := match.New(
		packet.New(
			packet.WithName("allowed-api-request"),
			packet.WithSrcAddr("192.0.2.10"),
			packet.WithDstAddr("198.51.100.25"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(54000),
			packet.WithDstPort(8443),
			packet.WithPayload([]byte("GET /v1/data?api_key=test-123 HTTP/1.1")),
		),
		match.WithExpectedVerdict(accept),
		match.WithExpectedRule("allow-api-key"),
	)

	blocked := match.New(
		packet.New(
			packet.WithName("blocked-api-request"),
			packet.WithSrcAddr("192.0.2.11"),
			packet.WithDstAddr("198.51.100.25"),
			packet.WithProto(proto.TCP),
			packet.WithSrcPort(54001),
			packet.WithDstPort(8443),
			packet.WithPayload([]byte("GET /v1/data HTTP/1.1")),
		),
		match.WithExpectedVerdict(rule.Drop),
		match.WithExpectedRule("table payload-policy default action"),
	)

	results := engine.Evaluate([]*match.MatchContext{allowed, blocked})

	Expect(results).To(HaveLen(2))
	Expect(results[0].VerdictMatches()).To(BeTrue())
	Expect(results[0].RuleMatches()).To(BeTrue())
	Expect(results[0].Trace).To(HaveLen(1))
	Expect(results[0].Trace[0].Name).To(Equal("allow-api-key"))

	Expect(results[1].VerdictMatches()).To(BeTrue())
	Expect(results[1].RuleMatches()).To(BeTrue())
	Expect(results[1].Trace).To(HaveLen(2))
	Expect(results[1].Trace[1].Name).To(Equal("table payload-policy default action"))

	Expect(allowAPIKey.PacketCount()).To(Equal(uint64(1)))
	Expect(policy.DefaultRule.PacketCount()).To(Equal(uint64(1)))
}
