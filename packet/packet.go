package packet

import (
	"bytes"
	"fmt"
	"net/netip"

	"github.com/mazdakn/firecore/proto"
)

type Option func(*Packet) error

func WithName(name string) Option {
	return func(p *Packet) error {
		p.Metadata.Name = name
		return nil
	}
}

func WithProto(p proto.Proto) Option {
	return func(pkt *Packet) error {
		pkt.Proto = p
		return nil
	}
}

func WithSrcPort(port uint16) Option {
	return func(p *Packet) error {
		p.Src = netip.AddrPortFrom(p.Src.Addr(), port)
		return nil
	}
}

func WithDstPort(port uint16) Option {
	return func(p *Packet) error {
		p.Dst = netip.AddrPortFrom(p.Dst.Addr(), port)
		return nil
	}
}

func WithSrcAddr(addr string) Option {
	return func(p *Packet) error {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("invalid source address: %q", addr)
		}
		p.Src = netip.AddrPortFrom(ip, p.Src.Port())
		return nil
	}
}

func WithDstAddr(addr string) Option {
	return func(p *Packet) error {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("invalid destination address: %q", addr)
		}
		p.Dst = netip.AddrPortFrom(ip, p.Dst.Port())
		return nil
	}
}

func WithSrcAddrPort(addrPort string) Option {
	return func(p *Packet) error {
		ap, err := netip.ParseAddrPort(addrPort)
		if err != nil {
			return fmt.Errorf("invalid source address:port: %q", addrPort)
		}
		p.Src = ap
		return nil
	}
}

func WithDstAddrPort(addrPort string) Option {
	return func(p *Packet) error {
		ap, err := netip.ParseAddrPort(addrPort)
		if err != nil {
			return fmt.Errorf("invalid destination address:port: %q", addrPort)
		}
		p.Dst = ap
		return nil
	}
}

func WithIngressIface(iface string) Option {
	return func(p *Packet) error {
		p.Metadata.IngressIface = iface
		return nil
	}
}

func WithEgressIface(iface string) Option {
	return func(p *Packet) error {
		p.Metadata.EgressIface = iface
		return nil
	}
}

func WithPayload(payload []byte) Option {
	return func(p *Packet) error {
		p.Payload = bytes.Clone(payload)
		return nil
	}
}

// WithSize sets the packet's full on-the-wire size, including headers. This
// is distinct from Payload, which callers may populate with only a slice of
// the packet's bytes (e.g. for payload matching) that does not reflect the
// packet's true size.
func WithSize(size uint32) Option {
	return func(p *Packet) error {
		p.Size = size
		return nil
	}
}

func New(opts ...Option) (*Packet, error) {
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
	Src netip.AddrPort
	Dst netip.AddrPort

	Proto proto.Proto

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
	return fmt.Sprintf("%s{%s:%d->%s:%d}", p.Proto, p.Src.Addr().String(), p.Src.Port(),
		p.Dst.Addr().String(), p.Dst.Port())
}
