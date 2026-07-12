package packet

import (
	"bytes"
	"fmt"
	"net"

	"github.com/mazdakn/firecore/proto"
)

type PacketOption func(*Packet) error

func WithName(name string) PacketOption {
	return func(p *Packet) error {
		p.Metadata.Name = name
		return nil
	}
}

func WithProto(p proto.Proto) PacketOption {
	return func(pkt *Packet) error {
		pkt.Proto = p
		return nil
	}
}

func WithSrcPort(port uint16) PacketOption {
	return func(p *Packet) error {
		p.SrcPort = port
		return nil
	}
}

func WithDstPort(port uint16) PacketOption {
	return func(p *Packet) error {
		p.DstPort = port
		return nil
	}
}

func WithSrcAddr(addr string) PacketOption {
	return func(p *Packet) error {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid source address: %q", addr)
		}
		p.SrcAddr = ip
		return nil
	}
}

func WithDstAddr(addr string) PacketOption {
	return func(p *Packet) error {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid destination address: %q", addr)
		}
		p.DstAddr = ip
		return nil
	}
}

func WithIngressIface(iface string) PacketOption {
	return func(p *Packet) error {
		p.Metadata.IngressIface = iface
		return nil
	}
}

func WithEgressIface(iface string) PacketOption {
	return func(p *Packet) error {
		p.Metadata.EgressIface = iface
		return nil
	}
}

func WithPayload(payload []byte) PacketOption {
	return func(p *Packet) error {
		p.Payload = bytes.Clone(payload)
		return nil
	}
}

func New(opts ...PacketOption) (*Packet, error) {
	p := Packet{
		Metadata: NewMetadata(),
	}
	for _, o := range opts {
		if err := o(&p); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

type Packet struct {
	SrcAddr net.IP
	DstAddr net.IP

	Proto proto.Proto

	SrcPort uint16
	DstPort uint16

	Payload []byte

	Metadata Metadata
}

func (p *Packet) String() string {
	if p.Metadata.Name != "" {
		return p.Metadata.Name
	}
	return fmt.Sprintf("%s{%s:%d->%s:%d}", p.Proto, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}
