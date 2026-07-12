package set

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestIfaceSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := NewIfaceSet()

	Expect(s.Add("eth0")).To(Succeed())
	Expect(s.Match("eth0")).To(BeTrue())
	Expect(s.Match("eth1")).To(BeFalse())
}

func TestIfaceSetAddUnsupportedType(t *testing.T) {
	RegisterTestingT(t)

	s := NewIfaceSet()
	Expect(s.Add(42)).To(HaveOccurred())
}

func TestIfaceSetMatch(t *testing.T) {
	RegisterTestingT(t)

	s := NewIfaceSet()

	Expect(s.Match("eth0")).To(BeFalse())

	Expect(s.Add("eth0")).To(Succeed())
	Expect(s.Match("eth0")).To(BeTrue())
	Expect(s.Match("eth1")).To(BeFalse())
}

func TestIfaceSetMatchWrongType(t *testing.T) {
	RegisterTestingT(t)

	s := NewIfaceSet()
	Expect(s.Add("eth0")).To(Succeed())
	Expect(s.Match(42)).To(BeFalse())
}

func TestIfaceSetStringOneIface(t *testing.T) {
	RegisterTestingT(t)

	s := NewIfaceSet()
	Expect(s.Add("eth0")).To(Succeed())
	Expect(s.String()).To(Equal("eth0"))
}

func TestIfaceSetStringMultipleIfaces(t *testing.T) {
	RegisterTestingT(t)

	s := NewIfaceSet()
	Expect(s.Add("eth1")).To(Succeed())
	Expect(s.Add("eth0")).To(Succeed())
	Expect(s.String()).To(Equal("{eth0,eth1}"))
}

func TestIfaceSetStringEmpty(t *testing.T) {
	RegisterTestingT(t)

	s := NewIfaceSet()
	Expect(s.String()).To(Equal("{}"))
}

func TestIfaceSetAddInvalid(t *testing.T) {
	RegisterTestingT(t)

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
			Expect(s.Add(tt.iface)).To(HaveOccurred())
			Expect(s.Match(tt.iface)).To(BeFalse())
		})
	}
}
