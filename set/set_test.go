package set

import (
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
