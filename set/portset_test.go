package set

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/firecore/port"
)

func TestPortSetAddPortStruct(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	// port.Port with only a name — number must be resolved from the name.
	Expect(ps.Add(port.Port{Name: "http"})).To(Succeed())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(443))).To(BeFalse())

	Expect(ps.Add(port.Port{Name: "https"})).To(Succeed())
	Expect(ps.Match(uint16(443))).To(BeTrue())

	// port.Port with both number and name — name takes precedence.
	ps2 := NewPortSet()
	Expect(ps2.Add(port.Port{Number: 0, Name: "ssh"})).To(Succeed())
	Expect(ps2.Match(uint16(22))).To(BeTrue())

	// port.Port with only a number.
	ps3 := NewPortSet()
	Expect(ps3.Add(port.Port{Number: 8080})).To(Succeed())
	Expect(ps3.Match(uint16(8080))).To(BeTrue())
}

func TestPortSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(443))).To(BeFalse())
}

func TestPortSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(uint16(443))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(uint16(80))).To(BeTrue())

	ps.Delete(uint16(80))
	Expect(ps.Match(uint16(80))).To(BeFalse())
	Expect(ps.Match(uint16(443))).To(BeTrue())
}

func TestPortSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	Expect(ps.Match(uint16(80))).To(BeFalse())

	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeFalse())
}

func TestPortSetStringOnePort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("80"))
}

func TestPortSetStringMultiplePorts(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	err := ps.Add(uint16(443))
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("{80,443}"))
}

func TestPortSetAddRange(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add(port.Port{Number: 1024, End: 65535})).To(Succeed())
	Expect(ps.Match(uint16(1024))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeTrue())
	Expect(ps.Match(uint16(65535))).To(BeTrue())
	Expect(ps.Match(uint16(1023))).To(BeFalse())
	Expect(ps.Match(uint16(80))).To(BeFalse())
}

func TestPortSetAddInvertedRangeFails(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add(port.Port{Number: 100, End: 50})).To(HaveOccurred())
	Expect(ps.Match(uint16(100))).To(BeFalse())
	Expect(ps.Match(uint16(75))).To(BeFalse())
	Expect(ps.Match(uint16(50))).To(BeFalse())
}

func TestPortSetAddRangeString(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.Match(uint16(1024))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeTrue())
	Expect(ps.Match(uint16(65535))).To(BeTrue())
	Expect(ps.Match(uint16(1023))).To(BeFalse())
}

func TestPortSetAddRangeAndSinglePort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add(uint16(80))).To(Succeed())
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeTrue())
	Expect(ps.Match(uint16(443))).To(BeFalse())
}

func TestPortSetStringWithRange(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.String()).To(Equal("1024-65535"))
}

func TestPortSetStringWithRangeAndPort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add(uint16(80))).To(Succeed())
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.String()).To(Equal("{80,1024-65535}"))
}
