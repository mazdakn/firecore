package conntrack

import (
	"testing"

	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	. "github.com/onsi/gomega"
)

func TestParseState(t *testing.T) {
	RegisterTestingT(t)

	state, err := ParseState("NEW")
	Expect(err).To(BeNil())
	Expect(state).To(Equal(StateNew))

	state, err = ParseState("established")
	Expect(err).To(BeNil())
	Expect(state).To(Equal(StateEstablished))

	_, err = ParseState("related")
	Expect(err).ToNot(BeNil())
}

func TestTrackerLookupAndCommitAccepted(t *testing.T) {
	RegisterTestingT(t)

	tracker := NewTracker()
	request := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithSrcPort(12345),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithDstPort(80),
		packet.WithProto(proto.TCP),
	)
	reply := packet.New(
		packet.WithSrcAddr("1.1.1.1"),
		packet.WithSrcPort(80),
		packet.WithDstAddr("10.0.0.1"),
		packet.WithDstPort(12345),
		packet.WithProto(proto.TCP),
	)

	Expect(tracker.Lookup(request)).To(Equal(StateNew))
	Expect(tracker.Lookup(reply)).To(Equal(StateNew))

	tracker.CommitAccepted(request)

	Expect(tracker.Lookup(request)).To(Equal(StateEstablished))
	Expect(tracker.Lookup(reply)).To(Equal(StateEstablished))
}
