package packet

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/firecore/proto"
)

func mustNewPacket(t testing.TB, opts ...Option) *Packet {
	t.Helper()
	pkt, err := New(opts...)
	Expect(err).ToNot(HaveOccurred())
	return pkt
}

func TestNewNilOptionFails(t *testing.T) {
	RegisterTestingT(t)

	pkt, err := New(WithSrcPort(80), nil)
	Expect(err).To(HaveOccurred())
	Expect(pkt).To(BeNil())
}

func TestWithName(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name    string
		pktName string
	}{
		{"Simple", "my-packet"},
		{"Empty", ""},
		{"WithSpaces", "http traffic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithName(tt.pktName))
			Expect(pkt.Metadata.Name).To(Equal(tt.pktName))
		})
	}
}

func TestPacketStringWithName(t *testing.T) {
	RegisterTestingT(t)

	// When name is set, String() should return the name
	pkt := mustNewPacket(t,
		WithName("web-traffic"),
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)
	Expect(pkt.String()).To(Equal("web-traffic"))

	// When name is empty, String() should return the detailed format
	pkt2 := mustNewPacket(t,
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)
	Expect(pkt2.String()).To(Equal("tcp{10.0.0.1:12345->192.168.1.1:80}"))
}

func TestNewEmpty(t *testing.T) {
	RegisterTestingT(t)

	pkt := mustNewPacket(t)
	Expect(pkt).ToNot(BeNil())
	Expect(pkt.SrcAddr).To(BeNil())
	Expect(pkt.DstAddr).To(BeNil())
	Expect(pkt.Proto).To(Equal(proto.Proto(0)))
	Expect(pkt.SrcPort).To(Equal(uint16(0)))
	Expect(pkt.DstPort).To(Equal(uint16(0)))
	Expect(pkt.Payload).To(BeNil())
	Expect(pkt.Size).To(Equal(uint32(0)))
}

func TestWithPayload(t *testing.T) {
	RegisterTestingT(t)

	original := []byte("GET /healthz HTTP/1.1")
	pkt := mustNewPacket(t, WithPayload(original))

	Expect(pkt.Payload).To(Equal([]byte("GET /healthz HTTP/1.1")))

	original[0] = 'P'
	Expect(pkt.Payload).To(Equal([]byte("GET /healthz HTTP/1.1")))
}

func TestWithSize(t *testing.T) {
	RegisterTestingT(t)

	pkt := mustNewPacket(t, WithSize(1500))
	Expect(pkt.Size).To(Equal(uint32(1500)))
}

func TestWithSizeIndependentOfPayload(t *testing.T) {
	RegisterTestingT(t)

	// Size reflects the full on-the-wire packet, which may be larger than
	// whatever slice of bytes Payload was populated with.
	pkt := mustNewPacket(t, WithPayload([]byte("hi")), WithSize(1500))
	Expect(pkt.Payload).To(Equal([]byte("hi")))
	Expect(pkt.Size).To(Equal(uint32(1500)))
}

func TestWithProto(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name  string
		proto proto.Proto
	}{
		{"TCP", proto.TCP},
		{"UDP", proto.UDP},
		{"ICMP", proto.ICMP},
		{"Custom", proto.Proto(255)},
		{"Zero", proto.Proto(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithProto(tt.proto))
			Expect(pkt.Proto).To(Equal(tt.proto))
		})
	}
}

func TestWithSrcPort(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name string
		port uint16
	}{
		{"HTTP", 80},
		{"HTTPS", 443},
		{"SSH", 22},
		{"HighPort", 65535},
		{"Zero", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithSrcPort(tt.port))
			Expect(pkt.SrcPort).To(Equal(tt.port))
		})
	}
}

func TestWithDstPort(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name string
		port uint16
	}{
		{"HTTP", 80},
		{"HTTPS", 443},
		{"DNS", 53},
		{"HighPort", 65535},
		{"Zero", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithDstPort(tt.port))
			Expect(pkt.DstPort).To(Equal(tt.port))
		})
	}
}

func TestWithSrcAddrIPv4(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name string
		addr string
	}{
		{"Localhost", "127.0.0.1"},
		{"Private10", "10.0.0.1"},
		{"Private172", "172.16.0.1"},
		{"Private192", "192.168.1.1"},
		{"Public", "8.8.8.8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithSrcAddr(tt.addr))
			Expect(pkt.SrcAddr).ToNot(BeNil())
			Expect(pkt.SrcAddr.String()).To(Equal(tt.addr))
		})
	}
}

func TestWithSrcAddrIPv6(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"Localhost", "::1", "::1"},
		{"Full", "2001:db8::1", "2001:db8::1"},
		{"LinkLocal", "fe80::1", "fe80::1"},
		{"Complex", "dead:beef::cafe", "dead:beef::cafe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithSrcAddr(tt.addr))
			Expect(pkt.SrcAddr).ToNot(BeNil())
			Expect(pkt.SrcAddr.String()).To(Equal(tt.expected))
		})
	}
}

func TestWithDstAddrIPv4(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name string
		addr string
	}{
		{"Localhost", "127.0.0.1"},
		{"Private10", "10.0.0.1"},
		{"Private172", "172.16.0.1"},
		{"Private192", "192.168.1.1"},
		{"Public", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithDstAddr(tt.addr))
			Expect(pkt.DstAddr).ToNot(BeNil())
			Expect(pkt.DstAddr.String()).To(Equal(tt.addr))
		})
	}
}

func TestWithDstAddrIPv6(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"Localhost", "::1", "::1"},
		{"Full", "2001:db8::1", "2001:db8::1"},
		{"LinkLocal", "fe80::1", "fe80::1"},
		{"Complex", "cafe::1", "cafe::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := mustNewPacket(t, WithDstAddr(tt.addr))
			Expect(pkt.DstAddr).ToNot(BeNil())
			Expect(pkt.DstAddr.String()).To(Equal(tt.expected))
		})
	}
}

func TestWithInvalidAddr(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name string
		addr string
	}{
		{"InvalidIPv4", "999.999.999.999"},
		{"InvalidIPv6", "gggg::1"},
		{"EmptyString", ""},
		{"NotAnIP", "not-an-ip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, err := New(WithSrcAddr(tt.addr))
			Expect(err).To(HaveOccurred())
			Expect(pkt).To(BeNil())

			pkt2, err := New(WithDstAddr(tt.addr))
			Expect(err).To(HaveOccurred())
			Expect(pkt2).To(BeNil())
		})
	}
}

func TestNewMultipleOptions(t *testing.T) {
	RegisterTestingT(t)

	pkt := mustNewPacket(t,
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)

	Expect(pkt.Proto).To(Equal(proto.TCP))
	Expect(pkt.SrcAddr.String()).To(Equal("10.0.0.1"))
	Expect(pkt.SrcPort).To(Equal(uint16(12345)))
	Expect(pkt.DstAddr.String()).To(Equal("192.168.1.1"))
	Expect(pkt.DstPort).To(Equal(uint16(80)))
}

func TestNewMultipleOptionsIPv6(t *testing.T) {
	RegisterTestingT(t)

	pkt := mustNewPacket(t,
		WithProto(17),
		WithSrcAddr("2001:db8::1"),
		WithSrcPort(54321),
		WithDstAddr("cafe::1"),
		WithDstPort(443),
	)

	Expect(pkt.Proto).To(Equal(proto.UDP))
	Expect(pkt.SrcAddr.String()).To(Equal("2001:db8::1"))
	Expect(pkt.SrcPort).To(Equal(uint16(54321)))
	Expect(pkt.DstAddr.String()).To(Equal("cafe::1"))
	Expect(pkt.DstPort).To(Equal(uint16(443)))
}

func TestPacketStringIPv4(t *testing.T) {
	RegisterTestingT(t)

	fullPacket := mustNewPacket(t,
		WithProto(proto.TCP),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)

	tcpPacket := mustNewPacket(t,
		WithProto(proto.TCP),
		WithSrcAddr("172.16.0.1"),
		WithSrcPort(50000),
		WithDstAddr("1.1.1.1"),
		WithDstPort(443),
	)

	udpPacket := mustNewPacket(t,
		WithProto(proto.UDP),
		WithSrcAddr("192.168.0.1"),
		WithSrcPort(55555),
		WithDstAddr("8.8.8.8"),
		WithDstPort(53),
	)

	tests := []struct {
		name     string
		packet   *Packet
		expected string
	}{
		{
			name:     "FullPacket",
			packet:   fullPacket,
			expected: "tcp{10.0.0.1:12345->192.168.1.1:80}",
		},
		{
			name:     "TCPPacket",
			packet:   tcpPacket,
			expected: "tcp{172.16.0.1:50000->1.1.1.1:443}",
		},
		{
			name:     "UDPPacket",
			packet:   udpPacket,
			expected: "udp{192.168.0.1:55555->8.8.8.8:53}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Expect(tt.packet.String()).To(Equal(tt.expected))
		})
	}
}

func TestPacketStringIPv6(t *testing.T) {
	RegisterTestingT(t)

	fullPacket := mustNewPacket(t,
		WithProto(proto.TCP),
		WithSrcAddr("2001:db8::1"),
		WithSrcPort(12345),
		WithDstAddr("cafe::1"),
		WithDstPort(80),
	)

	tcpPacket := mustNewPacket(t,
		WithProto(proto.TCP),
		WithSrcAddr("dead:beef::1"),
		WithSrcPort(44444),
		WithDstAddr("fe80::1"),
		WithDstPort(443),
	)

	tests := []struct {
		name     string
		packet   *Packet
		expected string
	}{
		{
			name:     "FullPacket",
			packet:   fullPacket,
			expected: "tcp{2001:db8::1:12345->cafe::1:80}",
		},
		{
			name:     "TCPPacket",
			packet:   tcpPacket,
			expected: "tcp{dead:beef::1:44444->fe80::1:443}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Expect(tt.packet.String()).To(Equal(tt.expected))
		})
	}
}

func TestPacketStringEmptyPacket(t *testing.T) {
	RegisterTestingT(t)

	pkt := mustNewPacket(t)
	result := pkt.String()
	// Empty packet will have nil IPs which will be formatted as <nil>
	Expect(result).To(Equal("0{<nil>:0-><nil>:0}"))
}

func TestPacketStringPartialPacket(t *testing.T) {
	RegisterTestingT(t)

	// Only protocol
	pkt1 := mustNewPacket(t, WithProto(proto.TCP))
	result1 := pkt1.String()
	Expect(result1).To(Equal("tcp{<nil>:0-><nil>:0}"))

	// Only ports
	pkt2 := mustNewPacket(t, WithSrcPort(1234), WithDstPort(5678))
	result2 := pkt2.String()
	Expect(result2).To(Equal("0{<nil>:1234-><nil>:5678}"))

	// Only addresses
	pkt3 := mustNewPacket(t, WithSrcAddr("10.0.0.1"), WithDstAddr("192.168.1.1"))
	result3 := pkt3.String()
	Expect(result3).To(Equal("0{10.0.0.1:0->192.168.1.1:0}"))
}

func TestPacketOptionsCanBeReused(t *testing.T) {
	RegisterTestingT(t)

	protoOpt := WithProto(proto.TCP)
	srcPortOpt := WithSrcPort(80)
	dstPortOpt := WithDstPort(443)

	pkt1 := mustNewPacket(t, protoOpt, srcPortOpt, dstPortOpt)
	pkt2 := mustNewPacket(t, protoOpt, srcPortOpt, dstPortOpt)

	Expect(pkt1.Proto).To(Equal(pkt2.Proto))
	Expect(pkt1.SrcPort).To(Equal(pkt2.SrcPort))
	Expect(pkt1.DstPort).To(Equal(pkt2.DstPort))
}

func TestPacketOptionsOrderIndependent(t *testing.T) {
	RegisterTestingT(t)

	pkt1 := mustNewPacket(t,
		WithProto(proto.TCP),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(80),
		WithDstAddr("192.168.1.1"),
		WithDstPort(443),
	)

	pkt2 := mustNewPacket(t,
		WithDstPort(443),
		WithDstAddr("192.168.1.1"),
		WithSrcPort(80),
		WithSrcAddr("10.0.0.1"),
		WithProto(proto.TCP),
	)

	Expect(pkt1.Proto).To(Equal(pkt2.Proto))
	Expect(pkt1.SrcAddr.String()).To(Equal(pkt2.SrcAddr.String()))
	Expect(pkt1.SrcPort).To(Equal(pkt2.SrcPort))
	Expect(pkt1.DstAddr.String()).To(Equal(pkt2.DstAddr.String()))
	Expect(pkt1.DstPort).To(Equal(pkt2.DstPort))
}
