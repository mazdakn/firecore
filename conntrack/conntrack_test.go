package conntrack

import (
	"sync"
	"testing"

	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
)

func mustNewPacket(t testing.TB, opts ...packet.Option) *packet.Packet {
	t.Helper()
	pkt, err := packet.New(opts...)
	if err != nil {
		t.Fatalf("packet.New: %v", err)
	}
	return pkt
}

func TestParseState(t *testing.T) {
	state, err := ParseState("NEW")
	if err != nil {
		t.Fatalf("ParseState(NEW) unexpected error: %v", err)
	}
	if state != StateNew {
		t.Errorf("ParseState(NEW) = %v; want %v", state, StateNew)
	}

	state, err = ParseState("established")
	if err != nil {
		t.Fatalf("ParseState(established) unexpected error: %v", err)
	}
	if state != StateEstablished {
		t.Errorf("ParseState(established) = %v; want %v", state, StateEstablished)
	}

	_, err = ParseState("related")
	if err == nil {
		t.Fatal("ParseState(related) expected error, got nil")
	}
}

func TestTrackerLookupAndCommitAccepted(t *testing.T) {
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
	if err != nil {
		t.Fatalf("tracker.Lookup(request) unexpected error: %v", err)
	}
	if state != StateNew {
		t.Errorf("state = %v; want %v", state, StateNew)
	}

	state, err = tracker.Lookup(reply)
	if err != nil {
		t.Fatalf("tracker.Lookup(reply) unexpected error: %v", err)
	}
	if state != StateNew {
		t.Errorf("state = %v; want %v", state, StateNew)
	}

	if err := tracker.CommitAccepted(request); err != nil {
		t.Fatalf("tracker.CommitAccepted(request) unexpected error: %v", err)
	}

	state, err = tracker.Lookup(request)
	if err != nil {
		t.Fatalf("tracker.Lookup(request) unexpected error: %v", err)
	}
	if state != StateEstablished {
		t.Errorf("state = %v; want %v", state, StateEstablished)
	}

	state, err = tracker.Lookup(reply)
	if err != nil {
		t.Fatalf("tracker.Lookup(reply) unexpected error: %v", err)
	}
	if state != StateEstablished {
		t.Errorf("state = %v; want %v", state, StateEstablished)
	}
}

func TestTrackerLookupReturnsErrorForNilPacket(t *testing.T) {
	tracker := NewTracker()
	if _, err := tracker.Lookup(nil); err == nil {
		t.Fatal("tracker.Lookup(nil) expected error, got nil")
	}
}

func TestTrackerCommitAcceptedReturnsErrorForNilPacket(t *testing.T) {
	tracker := NewTracker()
	if err := tracker.CommitAccepted(nil); err == nil {
		t.Fatal("tracker.CommitAccepted(nil) expected error, got nil")
	}
}

func TestTrackerConcurrentAccess(t *testing.T) {
	tracker := NewTracker()
	pkt := mustNewPacket(t,
		packet.WithSrcAddr("10.0.0.1"),
		packet.WithSrcPort(12345),
		packet.WithDstAddr("1.1.1.1"),
		packet.WithDstPort(80),
		packet.WithProto(proto.TCP),
	)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_, _ = tracker.Lookup(pkt)
				_ = tracker.CommitAccepted(pkt)
			}
		}()
	}
	wg.Wait()

	state, err := tracker.Lookup(pkt)
	if err != nil {
		t.Fatalf("tracker.Lookup(pkt) unexpected error: %v", err)
	}
	if state != StateEstablished {
		t.Errorf("state = %v; want %v", state, StateEstablished)
	}
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
