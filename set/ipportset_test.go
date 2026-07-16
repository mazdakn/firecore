package set

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"
)

func TestIPPortSetMatch(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPPortSet()
	Expect(s.Add("10.0.0.0/8,80")).To(Succeed())
	Expect(s.Add("192.168.1.10,1024-65535")).To(Succeed())
	Expect(s.Add("2001:db8::/64,0")).To(Succeed())

	Expect(s.Match(IPPortTuple{
		IP:   net.ParseIP("10.1.2.3"),
		Port: 80,
	})).To(BeTrue())
	Expect(s.Match(IPPortTuple{
		IP:   net.ParseIP("10.1.2.3"),
		Port: 443,
	})).To(BeFalse())
	Expect(s.Match(IPPortTuple{
		IP:   net.ParseIP("192.168.1.10"),
		Port: 8080,
	})).To(BeTrue())
	Expect(s.Match(IPPortTuple{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 0,
	})).To(BeTrue())
}

func TestIPPortSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPPortSet()
	Expect(s.Add("10.0.0.0/8,80")).To(Succeed())
	Expect(s.Add("192.168.1.10,1024-65535")).To(Succeed())
	Expect(s.Match(IPPortTuple{IP: net.ParseIP("10.1.2.3"), Port: 80})).To(BeTrue())

	Expect(s.Delete("10.0.0.0/8,80")).To(Succeed())
	Expect(s.Match(IPPortTuple{IP: net.ParseIP("10.1.2.3"), Port: 80})).To(BeFalse())
	Expect(s.Match(IPPortTuple{IP: net.ParseIP("192.168.1.10"), Port: 8080})).To(BeTrue())
}

func TestIPPortSetDeleteMissing(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPPortSet()
	Expect(s.Add("10.0.0.0/8,80")).To(Succeed())

	// Deleting a member that was never added is a no-op, not an error.
	Expect(s.Delete("192.168.1.10,443")).To(Succeed())
	Expect(s.Match(IPPortTuple{IP: net.ParseIP("10.1.2.3"), Port: 80})).To(BeTrue())
}

func TestIPPortSetDeleteInvalid(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPPortSet()
	Expect(s.Delete("10.0.0.0/8")).ToNot(Succeed())
	Expect(s.Delete(42)).ToNot(Succeed())
}

func TestIPPortSetAddInvalid(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPPortSet()
	Expect(s.Add("10.0.0.0/8")).ToNot(Succeed())
	Expect(s.Add("10.0.0.0/8,notport")).ToNot(Succeed())
}
