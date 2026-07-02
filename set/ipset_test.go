package set

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"
)

func TestIPSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(ipnet)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("192.168.0.1"))).To(BeFalse())
}

func TestIPSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(net1)
	Expect(err).NotTo(HaveOccurred())
	err = s.Add(net2)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())

	s.Delete(net1)
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeFalse())
	Expect(s.Match(net.ParseIP("192.168.1.1"))).To(BeTrue())
}

func TestIPSetMatch(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	Expect(s.Match(net.ParseIP("10.0.0.1"))).To(BeFalse())

	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(ipnet)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.Match(net.ParseIP("10.0.0.1"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("172.16.0.1"))).To(BeFalse())
}

func TestIPSetMatchMultipleNets(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(net1)
	Expect(err).NotTo(HaveOccurred())
	err = s.Add(net2)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("192.168.1.1"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("172.16.0.1"))).To(BeFalse())
}

func TestIPSetStringOneNet(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(ipnet)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.String()).To(Equal("10.0.0.0/8"))
}

func TestIPSetStringMultipleNets(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(net1)
	Expect(err).NotTo(HaveOccurred())
	err = s.Add(net2)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.String()).To(Equal("{10.0.0.0/8,192.168.0.0/16}"))
}
