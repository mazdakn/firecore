package set

import (
	"net"
	"testing"
)

func TestIPPortSetMatch(t *testing.T) {
	s := NewIPPortSet()
	if err := s.Add("10.0.0.0/8,80"); err != nil {
		t.Fatalf("s.Add(10.0.0.0/8,80) unexpected error: %v", err)
	}
	if err := s.Add("192.168.1.10,1024-65535"); err != nil {
		t.Fatalf("s.Add(192.168.1.10,1024-65535) unexpected error: %v", err)
	}
	if err := s.Add("2001:db8::/64,0"); err != nil {
		t.Fatalf("s.Add(2001:db8::/64,0) unexpected error: %v", err)
	}

	if !s.Match(IPPortTuple{
		IP:   net.ParseIP("10.1.2.3"),
		Port: 80,
	}) {
		t.Errorf("expected match for 10.1.2.3:80")
	}
	if s.Match(IPPortTuple{
		IP:   net.ParseIP("10.1.2.3"),
		Port: 443,
	}) {
		t.Errorf("expected no match for 10.1.2.3:443")
	}
	if !s.Match(IPPortTuple{
		IP:   net.ParseIP("192.168.1.10"),
		Port: 8080,
	}) {
		t.Errorf("expected match for 192.168.1.10:8080")
	}
	if !s.Match(IPPortTuple{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 0,
	}) {
		t.Errorf("expected match for 2001:db8::1:0")
	}
}

func TestIPPortSetDelete(t *testing.T) {
	s := NewIPPortSet()
	if err := s.Add("10.0.0.0/8,80"); err != nil {
		t.Fatalf("s.Add(10.0.0.0/8,80) unexpected error: %v", err)
	}
	if err := s.Add("192.168.1.10,1024-65535"); err != nil {
		t.Fatalf("s.Add(192.168.1.10,1024-65535) unexpected error: %v", err)
	}
	if !s.Match(IPPortTuple{IP: net.ParseIP("10.1.2.3"), Port: 80}) {
		t.Errorf("expected match for 10.1.2.3:80")
	}

	if err := s.Delete("10.0.0.0/8,80"); err != nil {
		t.Fatalf("s.Delete(10.0.0.0/8,80) unexpected error: %v", err)
	}
	if s.Match(IPPortTuple{IP: net.ParseIP("10.1.2.3"), Port: 80}) {
		t.Errorf("expected no match for 10.1.2.3:80 after delete")
	}
	if !s.Match(IPPortTuple{IP: net.ParseIP("192.168.1.10"), Port: 8080}) {
		t.Errorf("expected match for 192.168.1.10:8080")
	}
}

func TestIPPortSetDeleteMissing(t *testing.T) {
	s := NewIPPortSet()
	if err := s.Add("10.0.0.0/8,80"); err != nil {
		t.Fatalf("s.Add(10.0.0.0/8,80) unexpected error: %v", err)
	}

	// Deleting a member that was never added is a no-op, not an error.
	if err := s.Delete("192.168.1.10,443"); err != nil {
		t.Fatalf("s.Delete(192.168.1.10,443) unexpected error: %v", err)
	}
	if !s.Match(IPPortTuple{IP: net.ParseIP("10.1.2.3"), Port: 80}) {
		t.Errorf("expected match for 10.1.2.3:80")
	}
}

func TestIPPortSetDeleteInvalid(t *testing.T) {
	s := NewIPPortSet()
	if err := s.Delete("10.0.0.0/8"); err == nil {
		t.Fatal("s.Delete(10.0.0.0/8) expected error, got nil")
	}
	if err := s.Delete(42); err == nil {
		t.Fatal("s.Delete(42) expected error, got nil")
	}
}

func TestIPPortSetAddInvalid(t *testing.T) {
	s := NewIPPortSet()
	if err := s.Add("10.0.0.0/8"); err == nil {
		t.Fatal("s.Add(10.0.0.0/8) expected error, got nil")
	}
	if err := s.Add("10.0.0.0/8,notport"); err == nil {
		t.Fatal("s.Add(10.0.0.0/8,notport) expected error, got nil")
	}
}
