package conntrack

import (
	"testing"

	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	. "github.com/onsi/gomega"
)

func mustNewPacket(t testing.TB, opts ...packet.Option) *packet.Packet {
	t.Helper()
	pkt, err := packet.New(opts...)
	Expect(err).ToNot(HaveOccurred())
	return pkt
}

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
	request := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithSrcPort(12345),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithDstPort(80),
		packet.WithProto(proto.TCP),
	)
	reply := mustNewPacket(t,
		packet.WithSrcAddr("1.1.1.1"),
		packet.WithSrcPort(80),
		packet.WithDstAddr("10.0.0.1"),
		packet.WithDstPort(12345),
		packet.WithProto(proto.TCP),
	)

	state, err := tracker.Lookup(request)
	Expect(err).NotTo(HaveOccurred())
	Expect(state).To(Equal(StateNew))

	state, err = tracker.Lookup(reply)
	Expect(err).NotTo(HaveOccurred())
	Expect(state).To(Equal(StateNew))

	Expect(tracker.CommitAccepted(request)).To(Succeed())

	state, err = tracker.Lookup(request)
	Expect(err).NotTo(HaveOccurred())
	Expect(state).To(Equal(StateEstablished))

	state, err = tracker.Lookup(reply)
	Expect(err).NotTo(HaveOccurred())
	Expect(state).To(Equal(StateEstablished))
}

func TestTrackerLookupReturnsErrorForNilPacket(t *testing.T) {
	RegisterTestingT(t)

	tracker := NewTracker()
	_, err := tracker.Lookup(nil)
	Expect(err).To(HaveOccurred())
}

func TestTrackerCommitAcceptedReturnsErrorForNilPacket(t *testing.T) {
	RegisterTestingT(t)

	tracker := NewTracker()
	Expect(tracker.CommitAccepted(nil)).To(HaveOccurred())
}

func TestTrackerConcurrentAccess(t *testing.T) {
	RegisterTestingT(t)

	tracker := NewTracker()
	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithSrcPort(12345),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithDstPort(80),
		packet.WithProto(proto.TCP),
	)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, _ = tracker.Lookup(pkt)
				_ = tracker.CommitAccepted(pkt)
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	state, err := tracker.Lookup(pkt)
	Expect(err).NotTo(HaveOccurred())
	Expect(state).To(Equal(StateEstablished))
}

func BenchmarkTrackerLookup(b *testing.B) {
	tracker := NewTracker()
	pkt, _ := packet.New(
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithSrcPort(12345),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithDstPort(80),
		packet.WithProto(proto.TCP),
	)
	_ = tracker.CommitAccepted(pkt)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = tracker.Lookup(pkt)
	}
}
