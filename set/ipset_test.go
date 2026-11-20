package set

import (
	"net/netip"
	"testing"
)

func TestIPSetAdd(t *testing.T) {
	s := NewIPSet()
	prefix, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePrefix(10.0.0.0/8) unexpected error: %v", err)
	}
	err = s.Add(prefix)
	if err != nil {
		t.Fatalf("s.Add(prefix) unexpected error: %v", err)
	}
	if !s.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}
	if s.Match(netip.MustParseAddr("192.168.0.1")) {
		t.Errorf("expected no match for 192.168.0.1")
	}
}

func TestIPSetAddAddr(t *testing.T) {
	s := NewIPSet()
	addr := netip.MustParseAddr("10.1.2.3")
	if err := s.Add(addr); err != nil {
		t.Fatalf("s.Add(addr) unexpected error: %v", err)
	}
	if !s.Match(addr) {
		t.Errorf("expected match for 10.1.2.3")
	}
	if err := s.Delete(addr); err != nil {
		t.Fatalf("s.Delete(addr) unexpected error: %v", err)
	}
	if s.Match(addr) {
		t.Errorf("expected no match for 10.1.2.3 after delete")
	}
}

func TestIPSetAddInvalidPrefixOrAddr(t *testing.T) {
	s := NewIPSet()
	if err := s.Add(netip.Prefix{}); err == nil {
		t.Error("expected error adding invalid netip.Prefix")
	}
	if err := s.Add(netip.Addr{}); err == nil {
		t.Error("expected error adding invalid netip.Addr")
	}
	if err := s.Delete(netip.Prefix{}); err == nil {
		t.Error("expected error deleting invalid netip.Prefix")
	}
	if err := s.Delete(netip.Addr{}); err == nil {
		t.Error("expected error deleting invalid netip.Addr")
	}
}

func TestIPSetAddZeroPrefix(t *testing.T) {
	s := NewIPSet()
	if err := s.Add(netip.MustParsePrefix("0.0.0.0/0")); err != nil {
		t.Fatalf("unexpected error adding zero prefix net: %v", err)
	}
	if !s.Match(netip.MustParseAddr("203.0.113.1")) {
		t.Errorf("expected match for 203.0.113.1")
	}
}

func TestIPSetDelete(t *testing.T) {
	s := NewIPSet()
	net1, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePrefix(10.0.0.0/8) unexpected error: %v", err)
	}
	net2, err := netip.ParsePrefix("192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParsePrefix(192.168.0.0/16) unexpected error: %v", err)
	}
	if err := s.Add(net1); err != nil {
		t.Fatalf("s.Add(net1) unexpected error: %v", err)
	}
	if err := s.Add(net2); err != nil {
		t.Fatalf("s.Add(net2) unexpected error: %v", err)
	}
	if !s.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}

	if err := s.Delete(net1); err != nil {
		t.Fatalf("s.Delete(net1) unexpected error: %v", err)
	}
	if s.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("expected no match for 10.1.2.3 after delete")
	}
	if !s.Match(netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("expected match for 192.168.1.1")
	}
}

func TestIPSetDeleteString(t *testing.T) {
	s := NewIPSet()
	if err := s.Add("10.0.0.0/8"); err != nil {
		t.Fatalf("s.Add(10.0.0.0/8) unexpected error: %v", err)
	}
	if !s.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}

	if err := s.Delete("10.0.0.0/8"); err != nil {
		t.Fatalf("s.Delete(10.0.0.0/8) unexpected error: %v", err)
	}
	if s.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("expected no match for 10.1.2.3 after delete")
	}
}

func TestIPSetDeleteInvalid(t *testing.T) {
	s := NewIPSet()
	if err := s.Delete("not-a-cidr"); err == nil {
		t.Fatal("s.Delete(not-a-cidr) expected error, got nil")
	}
	if err := s.Delete(42); err == nil {
		t.Fatal("s.Delete(42) expected error, got nil")
	}
}

func TestIPSetMatch(t *testing.T) {
	s := NewIPSet()
	if s.Match(netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("expected no match on empty set")
	}

	prefix, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePrefix(10.0.0.0/8) unexpected error: %v", err)
	}
	if err := s.Add(prefix); err != nil {
		t.Fatalf("s.Add(prefix) unexpected error: %v", err)
	}
	if !s.Match(netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("expected match for 10.0.0.1")
	}
	if s.Match(netip.MustParseAddr("172.16.0.1")) {
		t.Errorf("expected no match for 172.16.0.1")
	}
}

func TestIPSetMatchMultipleNets(t *testing.T) {
	s := NewIPSet()
	net1, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePrefix(10.0.0.0/8) unexpected error: %v", err)
	}
	net2, err := netip.ParsePrefix("192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParsePrefix(192.168.0.0/16) unexpected error: %v", err)
	}
	if err := s.Add(net1); err != nil {
		t.Fatalf("s.Add(net1) unexpected error: %v", err)
	}
	if err := s.Add(net2); err != nil {
		t.Fatalf("s.Add(net2) unexpected error: %v", err)
	}
	if !s.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}
	if !s.Match(netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("expected match for 192.168.1.1")
	}
	if s.Match(netip.MustParseAddr("172.16.0.1")) {
		t.Errorf("expected no match for 172.16.0.1")
	}
}

func TestIPSetStringOneNet(t *testing.T) {
	s := NewIPSet()
	prefix, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePrefix(10.0.0.0/8) unexpected error: %v", err)
	}
	if err := s.Add(prefix); err != nil {
		t.Fatalf("s.Add(prefix) unexpected error: %v", err)
	}
	if got := s.String(); got != "10.0.0.0/8" {
		t.Errorf("s.String() = %q; want 10.0.0.0/8", got)
	}
}

func TestIPSetStringMultipleNets(t *testing.T) {
	s := NewIPSet()
	net1, err := netip.ParsePrefix("192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParsePrefix(192.168.0.0/16) unexpected error: %v", err)
	}
	net2, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePrefix(10.0.0.0/8) unexpected error: %v", err)
	}
	if err := s.Add(net1); err != nil {
		t.Fatalf("s.Add(net1) unexpected error: %v", err)
	}
	if err := s.Add(net2); err != nil {
		t.Fatalf("s.Add(net2) unexpected error: %v", err)
	}
	if got := s.String(); got != "{10.0.0.0/8,192.168.0.0/16}" {
		t.Errorf("s.String() = %q; want {10.0.0.0/8,192.168.0.0/16}", got)
	}
}

func TestIPSetAddSingleIP(t *testing.T) {
	s := NewIPSet()
	if err := s.Add("10.0.0.1"); err != nil {
		t.Fatalf("s.Add(10.0.0.1) unexpected error: %v", err)
	}
	if err := s.Add("2001:db8::1"); err != nil {
		t.Fatalf("s.Add(2001:db8::1) unexpected error: %v", err)
	}

	if !s.Match(netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("expected match for 10.0.0.1")
	}
	if s.Match(netip.MustParseAddr("10.0.0.2")) {
		t.Errorf("expected no match for 10.0.0.2")
	}
	if !s.Match(netip.MustParseAddr("2001:db8::1")) {
		t.Errorf("expected match for 2001:db8::1")
	}
	if s.Match(netip.MustParseAddr("2001:db8::2")) {
		t.Errorf("expected no match for 2001:db8::2")
	}
}

func TestIPSetDeleteSingleIP(t *testing.T) {
	s := NewIPSet()
	if err := s.Add("10.0.0.1"); err != nil {
		t.Fatalf("s.Add(10.0.0.1) unexpected error: %v", err)
	}
	if !s.Match(netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("expected match for 10.0.0.1")
	}

	if err := s.Delete("10.0.0.1"); err != nil {
		t.Fatalf("s.Delete(10.0.0.1) unexpected error: %v", err)
	}
	if s.Match(netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("expected no match for 10.0.0.1 after delete")
	}
}

func TestParseCIDROrIP(t *testing.T) {
	t.Run("valid CIDRs", func(t *testing.T) {
		ipnet, err := parseCIDROrIP("10.0.0.0/8")
		if err != nil {
			t.Fatalf("parseCIDROrIP(10.0.0.0/8) unexpected error: %v", err)
		}
		if got := ipnet.String(); got != "10.0.0.0/8" {
			t.Errorf("ipnet.String() = %q; want 10.0.0.0/8", got)
		}

		ipnet6, err := parseCIDROrIP("2001:db8::/32")
		if err != nil {
			t.Fatalf("parseCIDROrIP(2001:db8::/32) unexpected error: %v", err)
		}
		if got := ipnet6.String(); got != "2001:db8::/32" {
			t.Errorf("ipnet6.String() = %q; want 2001:db8::/32", got)
		}
	})

	t.Run("valid single IPs", func(t *testing.T) {
		ipnet4, err := parseCIDROrIP("192.168.1.1")
		if err != nil {
			t.Fatalf("parseCIDROrIP(192.168.1.1) unexpected error: %v", err)
		}
		if got := ipnet4.String(); got != "192.168.1.1/32" {
			t.Errorf("ipnet4.String() = %q; want 192.168.1.1/32", got)
		}
		if ipnet4.Bits() != 32 {
			t.Errorf("ipnet4.Bits() = %d; want 32", ipnet4.Bits())
		}

		ipnet6, err := parseCIDROrIP("2001:db8::1")
		if err != nil {
			t.Fatalf("parseCIDROrIP(2001:db8::1) unexpected error: %v", err)
		}
		if got := ipnet6.String(); got != "2001:db8::1/128" {
			t.Errorf("ipnet6.String() = %q; want 2001:db8::1/128", got)
		}
		if ipnet6.Bits() != 128 {
			t.Errorf("ipnet6.Bits() = %d; want 128", ipnet6.Bits())
		}
	})

	t.Run("invalid inputs", func(t *testing.T) {
		invalidInputs := []string{
			"invalid-ip",
			"256.256.256.256",
			"10.0.0.0/33",
			"not-an-ip/24",
		}
		for _, input := range invalidInputs {
			if _, err := parseCIDROrIP(input); err == nil {
				t.Errorf("expected error for input %q, got nil", input)
			}
		}
	})
}
