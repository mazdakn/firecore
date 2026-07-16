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

func TestIPSetAddInvalidIPNet(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	Expect(s.Add((*net.IPNet)(nil))).To(HaveOccurred())
	Expect(s.Add(&net.IPNet{})).To(HaveOccurred())
	Expect(s.Add(&net.IPNet{IP: net.ParseIP("10.0.0.0")})).To(HaveOccurred())
	Expect(s.Add(&net.IPNet{Mask: net.CIDRMask(8, 32)})).To(HaveOccurred())
	Expect(s.Add(&net.IPNet{
		IP:   net.ParseIP("10.0.0.0").To4(),
		Mask: net.CIDRMask(64, 128),
	})).To(HaveOccurred())
	Expect(s.Add(&net.IPNet{
		IP:   net.ParseIP("10.0.0.0").To4(),
		Mask: net.IPMask{0x0f, 0xff, 0xff, 0xff},
	})).To(HaveOccurred())
}

func TestIPSetAddZeroPrefixIPNet(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	Expect(s.Add(&net.IPNet{
		IP:   net.ParseIP("0.0.0.0").To4(),
		Mask: net.CIDRMask(0, 32),
	})).To(Succeed())
	Expect(s.Match(net.ParseIP("203.0.113.1"))).To(BeTrue())
}

func TestIPSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	Expect(s.Add(net1)).To(Succeed())
	Expect(s.Add(net2)).To(Succeed())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())

	Expect(s.Delete(net1)).To(Succeed())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeFalse())
	Expect(s.Match(net.ParseIP("192.168.1.1"))).To(BeTrue())
}

func TestIPSetDeleteString(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	Expect(s.Add("10.0.0.0/8")).To(Succeed())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())

	Expect(s.Delete("10.0.0.0/8")).To(Succeed())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeFalse())
}

func TestIPSetDeleteInvalid(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	Expect(s.Delete("not-a-cidr")).To(HaveOccurred())
	Expect(s.Delete(42)).To(HaveOccurred())
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
