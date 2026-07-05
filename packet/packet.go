package packet

import (
	"bytes"
	"fmt"
	"net"

	"github.com/mazdakn/firecore/proto"
)

type PacketOption func(*Packet)

func WithName(name string) PacketOption {
	return func(p *Packet) {
		p.Metadata.Name = name
	}
}

func WithProto(p proto.Proto) PacketOption {
	return func(pkt *Packet) {
		pkt.Proto = p
	}
}

func WithSrcPort(port uint16) PacketOption {
	return func(p *Packet) {
		p.SrcPort = port
	}
}

func WithDstPort(port uint16) PacketOption {
	return func(p *Packet) {
		p.DstPort = port
	}
}

func WithSrcAddr(addr string) PacketOption {
	return func(p *Packet) {
		p.SrcAddr = net.ParseIP(addr)
	}
}

func WithDstAddr(addr string) PacketOption {
	return func(p *Packet) {
		p.DstAddr = net.ParseIP(addr)
	}
}

func WithIngressIface(iface string) PacketOption {
	return func(p *Packet) {
		p.Metadata.IngressIface = iface
	}
}

func WithEgressIface(iface string) PacketOption {
	return func(p *Packet) {
		p.Metadata.EgressIface = iface
	}
}

func WithPayload(payload []byte) PacketOption {
	return func(p *Packet) {
		p.Payload = bytes.Clone(payload)
	}
}

func New(opts ...PacketOption) *Packet {
	p := Packet{
		Metadata: NewMetadata(),
	}
	for _, o := range opts {
		o(&p)
	}
	return &p
}

type Packet struct {
	SrcAddr net.IP
	DstAddr net.IP

	Proto proto.Proto

	SrcPort uint16
	DstPort uint16

	Payload []byte

	Metadata *Metadata
}

func (p *Packet) String() string {
	if p.Metadata.Name != "" {
		return p.Metadata.Name
	}
	return fmt.Sprintf("%s{%s:%d->%s:%d}", p.Proto, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}
