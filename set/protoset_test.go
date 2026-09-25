package set

import (
	"testing"

	"github.com/mazdakn/firecore/proto"
)

func TestProtoSetAdd(t *testing.T) {
	ps := NewProtoSet()

	err := ps.Add(proto.TCP)
	if err != nil {
		t.Fatalf("ps.Add(TCP) unexpected error: %v", err)
	}
	if !ps.Match(proto.TCP) {
		t.Errorf("expected match for TCP")
	}
	if ps.Match(proto.UDP) {
		t.Errorf("expected no match for UDP")
	}
}

func TestProtoSetDelete(t *testing.T) {
	ps := NewProtoSet()

	err := ps.Add(proto.TCP)
	if err != nil {
		t.Fatalf("ps.Add(TCP) unexpected error: %v", err)
	}
	err = ps.Add(proto.UDP)
	if err != nil {
		t.Fatalf("ps.Add(UDP) unexpected error: %v", err)
	}
	if !ps.Match(proto.TCP) {
		t.Errorf("expected match for TCP")
	}

	if err := ps.Delete(proto.TCP); err != nil {
		t.Fatalf("ps.Delete(TCP) unexpected error: %v", err)
	}
	if ps.Match(proto.TCP) {
		t.Errorf("expected no match for TCP after delete")
	}
	if !ps.Match(proto.UDP) {
		t.Errorf("expected match for UDP")
	}
}

func TestProtoSetDeleteString(t *testing.T) {
	ps := NewProtoSet()
	if err := ps.Add(proto.TCP); err != nil {
		t.Fatalf("ps.Add(TCP) unexpected error: %v", err)
	}
	if !ps.Match(proto.TCP) {
		t.Errorf("expected match for TCP")
	}

	if err := ps.Delete("tcp"); err != nil {
		t.Fatalf("ps.Delete(tcp) unexpected error: %v", err)
	}
	if ps.Match(proto.TCP) {
		t.Errorf("expected no match for TCP after delete")
	}
}

func TestProtoSetDeleteInvalidString(t *testing.T) {
	ps := NewProtoSet()
	if err := ps.Delete("not-a-protocol"); err == nil {
		t.Fatal("ps.Delete(not-a-protocol) expected error, got nil")
	}
}

func TestProtoSetDeleteUnsupportedType(t *testing.T) {
	ps := NewProtoSet()
	if err := ps.Delete(3.14); err == nil {
		t.Fatal("ps.Delete(3.14) expected error, got nil")
	}
}

func TestProtoSetMatch(t *testing.T) {
	ps := NewProtoSet()

	if ps.Match(proto.TCP) {
		t.Errorf("expected no match on empty set")
	}

	err := ps.Add(proto.TCP)
	if err != nil {
		t.Fatalf("ps.Add(TCP) unexpected error: %v", err)
	}
	if !ps.Match(proto.TCP) {
		t.Errorf("expected match for TCP")
	}
	if ps.Match(proto.UDP) {
		t.Errorf("expected no match for UDP")
	}
}

func TestProtoSetStringOneProto(t *testing.T) {
	ps := NewProtoSet()
	err := ps.Add(proto.TCP)
	if err != nil {
		t.Fatalf("ps.Add(TCP) unexpected error: %v", err)
	}
	if got := ps.String(); got != "tcp" {
		t.Errorf("ps.String() = %q; want tcp", got)
	}
}

func TestProtoSetStringMultipleProtos(t *testing.T) {
	ps := NewProtoSet()
	err := ps.Add(proto.UDP)
	if err != nil {
		t.Fatalf("ps.Add(UDP) unexpected error: %v", err)
	}
	err = ps.Add(proto.TCP)
	if err != nil {
		t.Fatalf("ps.Add(TCP) unexpected error: %v", err)
	}
	if got := ps.String(); got != "{tcp,udp}" {
		t.Errorf("ps.String() = %q; want {tcp,udp}", got)
	}
}
