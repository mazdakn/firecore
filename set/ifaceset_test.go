package set

import (
	"testing"
)

func TestIfaceSetAdd(t *testing.T) {
	s := NewIfaceSet()

	if err := s.Add("eth0"); err != nil {
		t.Fatalf("s.Add(eth0) unexpected error: %v", err)
	}
	if !s.Match("eth0") {
		t.Errorf("s.Match(eth0) = false; want true")
	}
	if s.Match("eth1") {
		t.Errorf("s.Match(eth1) = true; want false")
	}
}

func TestIfaceSetAddUnsupportedType(t *testing.T) {
	s := NewIfaceSet()
	if err := s.Add(42); err == nil {
		t.Fatal("s.Add(42) expected error, got nil")
	}
}

func TestIfaceSetDelete(t *testing.T) {
	s := NewIfaceSet()
	if err := s.Add("eth0"); err != nil {
		t.Fatalf("s.Add(eth0) unexpected error: %v", err)
	}
	if err := s.Add("eth1"); err != nil {
		t.Fatalf("s.Add(eth1) unexpected error: %v", err)
	}
	if !s.Match("eth0") {
		t.Errorf("s.Match(eth0) = false; want true")
	}

	if err := s.Delete("eth0"); err != nil {
		t.Fatalf("s.Delete(eth0) unexpected error: %v", err)
	}
	if s.Match("eth0") {
		t.Errorf("s.Match(eth0) = true; want false after delete")
	}
	if !s.Match("eth1") {
		t.Errorf("s.Match(eth1) = false; want true")
	}
}

func TestIfaceSetDeleteUnsupportedType(t *testing.T) {
	s := NewIfaceSet()
	if err := s.Delete(42); err == nil {
		t.Fatal("s.Delete(42) expected error, got nil")
	}
}

func TestIfaceSetMatch(t *testing.T) {
	s := NewIfaceSet()

	if s.Match("eth0") {
		t.Errorf("s.Match(eth0) on empty set = true; want false")
	}

	if err := s.Add("eth0"); err != nil {
		t.Fatalf("s.Add(eth0) unexpected error: %v", err)
	}
	if !s.Match("eth0") {
		t.Errorf("s.Match(eth0) = false; want true")
	}
	if s.Match("eth1") {
		t.Errorf("s.Match(eth1) = true; want false")
	}
}

func TestIfaceSetMatchWrongType(t *testing.T) {
	s := NewIfaceSet()
	if err := s.Add("eth0"); err != nil {
		t.Fatalf("s.Add(eth0) unexpected error: %v", err)
	}
	if s.Match(42) {
		t.Errorf("s.Match(42) = true; want false")
	}
}

func TestIfaceSetStringOneIface(t *testing.T) {
	s := NewIfaceSet()
	if err := s.Add("eth0"); err != nil {
		t.Fatalf("s.Add(eth0) unexpected error: %v", err)
	}
	if got := s.String(); got != "eth0" {
		t.Errorf("s.String() = %q; want eth0", got)
	}
}

func TestIfaceSetStringMultipleIfaces(t *testing.T) {
	s := NewIfaceSet()
	if err := s.Add("eth1"); err != nil {
		t.Fatalf("s.Add(eth1) unexpected error: %v", err)
	}
	if err := s.Add("eth0"); err != nil {
		t.Fatalf("s.Add(eth0) unexpected error: %v", err)
	}
	if got := s.String(); got != "{eth0,eth1}" {
		t.Errorf("s.String() = %q; want {eth0,eth1}", got)
	}
}

func TestIfaceSetStringEmpty(t *testing.T) {
	s := NewIfaceSet()
	if got := s.String(); got != "{}" {
		t.Errorf("s.String() = %q; want {}", got)
	}
}

func TestIfaceSetAddInvalid(t *testing.T) {
	tests := []struct {
		name  string
		iface string
	}{
		{"Empty", ""},
		{"TooLong", "this-name-is-too-long"},
		{"ContainsSlash", "eth0/1"},
		{"ContainsSpace", "eth 0"},
		{"ContainsTab", "eth\t0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewIfaceSet()
			if err := s.Add(tt.iface); err == nil {
				t.Errorf("s.Add(%q) expected error, got nil", tt.iface)
			}
			if s.Match(tt.iface) {
				t.Errorf("s.Match(%q) = true; want false", tt.iface)
			}
		})
	}
}
