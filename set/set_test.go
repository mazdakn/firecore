package set

import (
	"net/netip"
	"testing"
)

func TestSetAdd(t *testing.T) {
	s := New[string]()

	s.Add("foo")
	if !s.Exists("foo") {
		t.Error("expected foo to exist in set")
	}
	if s.Exists("bar") {
		t.Error("expected bar to not exist in set")
	}
}

func TestSetDelete(t *testing.T) {
	s := New[int]()

	s.Add(1)
	s.Add(2)
	if !s.Exists(1) {
		t.Error("expected 1 to exist in set")
	}

	s.Delete(1)
	if s.Exists(1) {
		t.Error("expected 1 to not exist after delete")
	}
	if !s.Exists(2) {
		t.Error("expected 2 to exist in set")
	}
}

func TestSetExists(t *testing.T) {
	s := New[string]()

	if s.Exists("missing") {
		t.Error("expected missing to not exist in set")
	}

	s.Add("present")
	if !s.Exists("present") {
		t.Error("expected present to exist in set")
	}
	if s.Exists("missing") {
		t.Error("expected missing to not exist in set")
	}
}

func TestSetTypes(t *testing.T) {
	if got := NewIPSet().Type(); got != TypeIP {
		t.Errorf("NewIPSet().Type() = %v; want %v", got, TypeIP)
	}
	if got := NewPortSet().Type(); got != TypePort {
		t.Errorf("NewPortSet().Type() = %v; want %v", got, TypePort)
	}
	if got := NewProtoSet().Type(); got != TypeProto {
		t.Errorf("NewProtoSet().Type() = %v; want %v", got, TypeProto)
	}
	if got := NewIPPortSet().Type(); got != TypeIPPort {
		t.Errorf("NewIPPortSet().Type() = %v; want %v", got, TypeIPPort)
	}
	if got := NewIfaceSet().Type(); got != TypeIface {
		t.Errorf("NewIfaceSet().Type() = %v; want %v", got, TypeIface)
	}
}

func TestEndpointSetMatchEndpoint(t *testing.T) {
	ap := netip.MustParseAddrPort("10.1.2.3:443")
	otherAP := netip.MustParseAddrPort("192.168.1.1:80")

	ipSet := NewIPSet()
	if err := ipSet.Add("10.0.0.0/8"); err != nil {
		t.Fatalf("ipSet.Add: %v", err)
	}
	portSet := NewPortSet()
	if err := portSet.Add(uint16(443)); err != nil {
		t.Fatalf("portSet.Add: %v", err)
	}
	ipPortSet := NewIPPortSet()
	if err := ipPortSet.Add("10.0.0.0/8,443"); err != nil {
		t.Fatalf("ipPortSet.Add: %v", err)
	}
	ifaceSet := NewIfaceSet()
	if err := ifaceSet.Add("eth0"); err != nil {
		t.Fatalf("ifaceSet.Add: %v", err)
	}

	cases := []struct {
		name  string
		set   EndpointSet
		match bool
		ap    netip.AddrPort
		iface string
	}{
		{"ip-hit", ipSet, true, ap, "eth1"},
		{"ip-miss", ipSet, false, otherAP, "eth0"},
		{"port-hit", portSet, true, ap, "eth1"},
		{"port-miss", portSet, false, otherAP, "eth0"},
		{"ipport-hit", ipPortSet, true, ap, "eth1"},
		{"ipport-miss", ipPortSet, false, otherAP, "eth0"},
		{"iface-hit", ifaceSet, true, otherAP, "eth0"},
		{"iface-miss", ifaceSet, false, ap, "eth1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.set.MatchEndpoint(tc.ap, tc.iface); got != tc.match {
				t.Errorf("MatchEndpoint(%v, %q) = %v; want %v", tc.ap, tc.iface, got, tc.match)
			}
		})
	}

	// ProtoSet must not satisfy EndpointSet.
	var ps Set = NewProtoSet()
	if _, ok := ps.(EndpointSet); ok {
		t.Error("ProtoSet should not implement EndpointSet")
	}
}
