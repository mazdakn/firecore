package set

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := New[string]()

	s.Add("foo")
	Expect(s.Exists("foo")).To(BeTrue())
	Expect(s.Exists("bar")).To(BeFalse())
}

func TestSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := New[int]()

	s.Add(1)
	s.Add(2)
	Expect(s.Exists(1)).To(BeTrue())

	s.Delete(1)
	Expect(s.Exists(1)).To(BeFalse())
	Expect(s.Exists(2)).To(BeTrue())
}

func TestSetExists(t *testing.T) {
	RegisterTestingT(t)

	s := New[string]()

	Expect(s.Exists("missing")).To(BeFalse())

	s.Add("present")
	Expect(s.Exists("present")).To(BeTrue())
	Expect(s.Exists("missing")).To(BeFalse())
}

func TestSetTypes(t *testing.T) {
	RegisterTestingT(t)

	Expect(NewIPSet().Type()).To(Equal(TypeIP))
	Expect(NewPortSet().Type()).To(Equal(TypePort))
	Expect(NewProtoSet().Type()).To(Equal(TypeProto))
	Expect(NewIPPortSet().Type()).To(Equal(TypeIPPort))
	Expect(NewIfaceSet().Type()).To(Equal(TypeIface))
}
