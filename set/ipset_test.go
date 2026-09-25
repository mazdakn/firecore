package set

import (
	"net"
	"testing"
)

func TestIPSetAdd(t *testing.T) {
	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR(10.0.0.0/8) unexpected error: %v", err)
	}
	err = s.Add(ipnet)
	if err != nil {
		t.Fatalf("s.Add(ipnet) unexpected error: %v", err)
	}
	if !s.Match(net.ParseIP("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}
	if s.Match(net.ParseIP("192.168.0.1")) {
		t.Errorf("expected no match for 192.168.0.1")
	}
}

func TestIPSetAddInvalidIPNet(t *testing.T) {
	s := NewIPSet()
	if err := s.Add((*net.IPNet)(nil)); err == nil {
		t.Error("expected error adding nil *net.IPNet")
	}
	if err := s.Add(&net.IPNet{}); err == nil {
		t.Error("expected error adding empty net.IPNet")
	}
	if err := s.Add(&net.IPNet{IP: net.ParseIP("10.0.0.0")}); err == nil {
		t.Error("expected error adding net.IPNet with nil Mask")
	}
	if err := s.Add(&net.IPNet{Mask: net.CIDRMask(8, 32)}); err == nil {
		t.Error("expected error adding net.IPNet with nil IP")
	}
	if err := s.Add(&net.IPNet{
		IP:   net.ParseIP("10.0.0.0").To4(),
		Mask: net.CIDRMask(64, 128),
	}); err == nil {
		t.Error("expected error adding IPv4 with IPv6 mask length")
	}
	if err := s.Add(&net.IPNet{
		IP:   net.ParseIP("10.0.0.0").To4(),
		Mask: net.IPMask{0x0f, 0xff, 0xff, 0xff},
	}); err == nil {
		t.Error("expected error adding non-contiguous mask")
	}
}

func TestIPSetAddZeroPrefixIPNet(t *testing.T) {
	s := NewIPSet()
	if err := s.Add(&net.IPNet{
		IP:   net.ParseIP("0.0.0.0").To4(),
		Mask: net.CIDRMask(0, 32),
	}); err != nil {
		t.Fatalf("unexpected error adding zero prefix net: %v", err)
	}
	if !s.Match(net.ParseIP("203.0.113.1")) {
		t.Errorf("expected match for 203.0.113.1")
	}
}

func TestIPSetDelete(t *testing.T) {
	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR(10.0.0.0/8) unexpected error: %v", err)
	}
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParseCIDR(192.168.0.0/16) unexpected error: %v", err)
	}
	if err := s.Add(net1); err != nil {
		t.Fatalf("s.Add(net1) unexpected error: %v", err)
	}
	if err := s.Add(net2); err != nil {
		t.Fatalf("s.Add(net2) unexpected error: %v", err)
	}
	if !s.Match(net.ParseIP("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}

	if err := s.Delete(net1); err != nil {
		t.Fatalf("s.Delete(net1) unexpected error: %v", err)
	}
	if s.Match(net.ParseIP("10.1.2.3")) {
		t.Errorf("expected no match for 10.1.2.3 after delete")
	}
	if !s.Match(net.ParseIP("192.168.1.1")) {
		t.Errorf("expected match for 192.168.1.1")
	}
}

func TestIPSetDeleteString(t *testing.T) {
	s := NewIPSet()
	if err := s.Add("10.0.0.0/8"); err != nil {
		t.Fatalf("s.Add(10.0.0.0/8) unexpected error: %v", err)
	}
	if !s.Match(net.ParseIP("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}

	if err := s.Delete("10.0.0.0/8"); err != nil {
		t.Fatalf("s.Delete(10.0.0.0/8) unexpected error: %v", err)
	}
	if s.Match(net.ParseIP("10.1.2.3")) {
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
	if s.Match(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected no match on empty set")
	}

	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR(10.0.0.0/8) unexpected error: %v", err)
	}
	if err := s.Add(ipnet); err != nil {
		t.Fatalf("s.Add(ipnet) unexpected error: %v", err)
	}
	if !s.Match(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected match for 10.0.0.1")
	}
	if s.Match(net.ParseIP("172.16.0.1")) {
		t.Errorf("expected no match for 172.16.0.1")
	}
}

func TestIPSetMatchMultipleNets(t *testing.T) {
	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR(10.0.0.0/8) unexpected error: %v", err)
	}
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParseCIDR(192.168.0.0/16) unexpected error: %v", err)
	}
	if err := s.Add(net1); err != nil {
		t.Fatalf("s.Add(net1) unexpected error: %v", err)
	}
	if err := s.Add(net2); err != nil {
		t.Fatalf("s.Add(net2) unexpected error: %v", err)
	}
	if !s.Match(net.ParseIP("10.1.2.3")) {
		t.Errorf("expected match for 10.1.2.3")
	}
	if !s.Match(net.ParseIP("192.168.1.1")) {
		t.Errorf("expected match for 192.168.1.1")
	}
	if s.Match(net.ParseIP("172.16.0.1")) {
		t.Errorf("expected no match for 172.16.0.1")
	}
}

func TestIPSetStringOneNet(t *testing.T) {
	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR(10.0.0.0/8) unexpected error: %v", err)
	}
	if err := s.Add(ipnet); err != nil {
		t.Fatalf("s.Add(ipnet) unexpected error: %v", err)
	}
	if got := s.String(); got != "10.0.0.0/8" {
		t.Errorf("s.String() = %q; want 10.0.0.0/8", got)
	}
}

func TestIPSetStringMultipleNets(t *testing.T) {
	s := NewIPSet()
	_, net1, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParseCIDR(192.168.0.0/16) unexpected error: %v", err)
	}
	_, net2, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR(10.0.0.0/8) unexpected error: %v", err)
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

	if !s.Match(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected match for 10.0.0.1")
	}
	if s.Match(net.ParseIP("10.0.0.2")) {
		t.Errorf("expected no match for 10.0.0.2")
	}
	if !s.Match(net.ParseIP("2001:db8::1")) {
		t.Errorf("expected match for 2001:db8::1")
	}
	if s.Match(net.ParseIP("2001:db8::2")) {
		t.Errorf("expected no match for 2001:db8::2")
	}
}

func TestIPSetDeleteSingleIP(t *testing.T) {
	s := NewIPSet()
	if err := s.Add("10.0.0.1"); err != nil {
		t.Fatalf("s.Add(10.0.0.1) unexpected error: %v", err)
	}
	if !s.Match(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected match for 10.0.0.1")
	}

	if err := s.Delete("10.0.0.1"); err != nil {
		t.Fatalf("s.Delete(10.0.0.1) unexpected error: %v", err)
	}
	if s.Match(net.ParseIP("10.0.0.1")) {
		t.Errorf("expected no match for 10.0.0.1 after delete")
	}
}
