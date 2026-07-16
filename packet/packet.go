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

// WithSize sets the packet's full on-the-wire size, including headers. This
// is distinct from Payload, which callers may populate with only a slice of
// the packet's bytes (e.g. for payload matching) that does not reflect the
// packet's true size.
func WithSize(size uint32) PacketOption {
	return func(p *Packet) error {
		p.Size = size
		return nil
	}
}

func New(opts ...PacketOption) (*Packet, error) {
	p := Packet{
		Metadata: NewMetadata(),
	}
	for _, o := range opts {
		if o == nil {
			return nil, fmt.Errorf("packet option must not be nil")
		}
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
	// Size is the packet's full on-the-wire size, including headers. Unlike
	// len(Payload), it reflects the true packet size even when Payload holds
	// only a partial slice of the packet's bytes.
	Size uint32

	Metadata Metadata
}

func (p *Packet) String() string {
	if p.Metadata.Name != "" {
		return p.Metadata.Name
	}
	return fmt.Sprintf("%s{%s:%d->%s:%d}", p.Proto, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}
