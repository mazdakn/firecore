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

	ps.Delete(proto.TCP)
	Expect(ps.Match(proto.TCP)).To(BeFalse())
	Expect(ps.Match(proto.UDP)).To(BeTrue())
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
