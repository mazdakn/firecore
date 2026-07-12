package firecore_test

import (
	"testing"

	firecore "github.com/mazdakn/firecore"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	. "github.com/onsi/gomega"
)

func TestPayloadRegexPolicy(t *testing.T) {
	RegisterTestingT(t)

	accept := mustParseAction(t, "accept")
	tcp := mustParseProto(t, "tcp")

	policy, err := firecore.NewTable("payload-policy", 1, firecore.Drop)
	Expect(err).NotTo(HaveOccurred())

	entry := newChain(t, "entry")

	allowAPIKey, err := firecore.NewRule(
		firecore.WithName("allow-api-key"),
		firecore.WithProto(tcp),
		firecore.WithDstPort(8443),
		firecore.WithPayload(`(?i)api_key=[A-Za-z0-9_-]+`),
		firecore.WithAction(accept),
	)
	Expect(err).NotTo(HaveOccurred())

	Expect(entry.AddRule(allowAPIKey)).To(Succeed())
	Expect(policy.AddChain(entry)).To(Succeed())
	Expect(policy.SetEntryChain("entry")).To(Succeed())

	engine := firecore.New()
	Expect(engine.AddTable(policy)).To(Succeed())

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
	Expect(err).NotTo(HaveOccurred())
	blockedResult, err := engine.Evaluate(blocked)

	Expect(err).NotTo(HaveOccurred())
	expectMatchResult(allowedResult, accept, "allow-api-key")
	Expect(allowedResult.Trace).To(HaveLen(1))
	Expect(allowedResult.Trace[0].Name).To(Equal("allow-api-key"))

	expectMatchResult(blockedResult, firecore.Drop, "table payload-policy default action")
	Expect(blockedResult.Trace).To(HaveLen(2))
	Expect(blockedResult.Trace[1].Name).To(Equal("table payload-policy default action"))

	Expect(allowAPIKey.PacketCount()).To(Equal(uint64(1)))
	Expect(policy.DefaultRule.PacketCount()).To(Equal(uint64(1)))
}
