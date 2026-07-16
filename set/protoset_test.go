package set

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/firecore/proto"
)

func TestProtoSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(proto.TCP)).To(BeTrue())
	Expect(ps.Match(proto.UDP)).To(BeFalse())
}

func TestProtoSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(proto.UDP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(proto.TCP)).To(BeTrue())

	Expect(ps.Delete(proto.TCP)).To(Succeed())
	Expect(ps.Match(proto.TCP)).To(BeFalse())
	Expect(ps.Match(proto.UDP)).To(BeTrue())
}

func TestProtoSetDeleteString(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	Expect(ps.Add(proto.TCP)).To(Succeed())
	Expect(ps.Match(proto.TCP)).To(BeTrue())

	Expect(ps.Delete("tcp")).To(Succeed())
	Expect(ps.Match(proto.TCP)).To(BeFalse())
}

func TestProtoSetDeleteInvalidString(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	Expect(ps.Delete("not-a-protocol")).To(HaveOccurred())
}

func TestProtoSetDeleteUnsupportedType(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	Expect(ps.Delete(3.14)).To(HaveOccurred())
}

func TestProtoSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	Expect(ps.Match(proto.TCP)).To(BeFalse())

	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(proto.TCP)).To(BeTrue())
	Expect(ps.Match(proto.UDP)).To(BeFalse())
}

func TestProtoSetStringOneProto(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("tcp"))
}

func TestProtoSetStringMultipleProtos(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	err := ps.Add(proto.UDP)
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("{tcp,udp}"))
}
