package packet

import (
	"bytes"
	"testing"

	"github.com/mazdakn/firecore/proto"
)

func mustNewPacket(t testing.TB, opts ...Option) *Packet {
	t.Helper()
	pkt, err := New(opts...)
	if err != nil {
		t.Fatalf("packet.New: %v", err)
	}
	return pkt
}

func TestNewNilOptionFails(t *testing.T) {
	pkt, err := New(WithSrcPort(80), nil)
	if err == nil {
		t.Fatal("New(..., nil) expected error, got nil")
	}
	if pkt != nil {
		t.Errorf("New(..., nil) expected nil pkt, got %v", pkt)
	}
}

func TestWithName(t *testing.T) {
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
			if pkt.Metadata.Name != tt.pktName {
				t.Errorf("Metadata.Name = %q; want %q", pkt.Metadata.Name, tt.pktName)
			}
		})
	}
}

func TestPacketStringWithName(t *testing.T) {
	// When name is set, String() should return the name
	pkt := mustNewPacket(t,
		WithName("web-traffic"),
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)
	if got := pkt.String(); got != "web-traffic" {
		t.Errorf("pkt.String() = %q; want %q", got, "web-traffic")
	}

	// When name is empty, String() should return the detailed format
	pkt2 := mustNewPacket(t,
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)
	if got := pkt2.String(); got != "tcp{10.0.0.1:12345->192.168.1.1:80}" {
		t.Errorf("pkt2.String() = %q; want %q", got, "tcp{10.0.0.1:12345->192.168.1.1:80}")
	}
}

func TestNewEmpty(t *testing.T) {
	pkt := mustNewPacket(t)
	if pkt == nil {
		t.Fatal("mustNewPacket returned nil")
	}
	if pkt.Src.IsValid() {
		t.Errorf("pkt.Src = %v; want invalid", pkt.Src)
	}
	if pkt.Dst.IsValid() {
		t.Errorf("pkt.Dst = %v; want invalid", pkt.Dst)
	}
	if pkt.Proto != proto.Proto(0) {
		t.Errorf("pkt.Proto = %v; want 0", pkt.Proto)
	}
	if pkt.Src.Port() != 0 {
		t.Errorf("pkt.Src.Port() = %d; want 0", pkt.Src.Port())
	}
	if pkt.Dst.Port() != 0 {
		t.Errorf("pkt.Dst.Port() = %d; want 0", pkt.Dst.Port())
	}
	if pkt.Payload != nil {
		t.Errorf("pkt.Payload = %v; want nil", pkt.Payload)
	}
	if pkt.Size != 0 {
		t.Errorf("pkt.Size = %d; want 0", pkt.Size)
	}
}

func TestWithPayload(t *testing.T) {
	original := []byte("GET /healthz HTTP/1.1")
	pkt := mustNewPacket(t, WithPayload(original))

	if !bytes.Equal(pkt.Payload, []byte("GET /healthz HTTP/1.1")) {
		t.Errorf("pkt.Payload = %q; want %q", pkt.Payload, "GET /healthz HTTP/1.1")
	}

	original[0] = 'P'
	if !bytes.Equal(pkt.Payload, []byte("GET /healthz HTTP/1.1")) {
		t.Errorf("pkt.Payload mutated; got %q; want %q", pkt.Payload, "GET /healthz HTTP/1.1")
	}
}

func TestWithSize(t *testing.T) {
	pkt := mustNewPacket(t, WithSize(1500))
	if pkt.Size != 1500 {
		t.Errorf("pkt.Size = %d; want 1500", pkt.Size)
	}
}

func TestWithSizeIndependentOfPayload(t *testing.T) {
	// Size reflects the full on-the-wire packet, which may be larger than
	// whatever slice of bytes Payload was populated with.
	pkt := mustNewPacket(t, WithPayload([]byte("hi")), WithSize(1500))
	if !bytes.Equal(pkt.Payload, []byte("hi")) {
		t.Errorf("pkt.Payload = %q; want %q", pkt.Payload, "hi")
	}
	if pkt.Size != 1500 {
		t.Errorf("pkt.Size = %d; want 1500", pkt.Size)
	}
}

func TestWithProto(t *testing.T) {
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
			if pkt.Proto != tt.proto {
				t.Errorf("pkt.Proto = %v; want %v", pkt.Proto, tt.proto)
			}
		})
	}
}

func TestWithSrcPort(t *testing.T) {
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
			if pkt.Src.Port() != tt.port {
				t.Errorf("pkt.Src.Port() = %d; want %d", pkt.Src.Port(), tt.port)
			}
		})
	}
}

func TestWithDstPort(t *testing.T) {
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
			if pkt.Dst.Port() != tt.port {
				t.Errorf("pkt.Dst.Port() = %d; want %d", pkt.Dst.Port(), tt.port)
			}
		})
	}
}

func TestWithSrcAddrIPv4(t *testing.T) {
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
			if !pkt.Src.Addr().IsValid() {
				t.Fatalf("pkt.Src.Addr() is invalid")
			}
			if got := pkt.Src.Addr().String(); got != tt.addr {
				t.Errorf("pkt.Src.Addr().String() = %q; want %q", got, tt.addr)
			}
		})
	}
}

func TestWithSrcAddrIPv6(t *testing.T) {
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
			if !pkt.Src.Addr().IsValid() {
				t.Fatalf("pkt.Src.Addr() is invalid")
			}
			if got := pkt.Src.Addr().String(); got != tt.expected {
				t.Errorf("pkt.Src.Addr().String() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestWithDstAddrIPv4(t *testing.T) {
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
			if !pkt.Dst.Addr().IsValid() {
				t.Fatalf("pkt.Dst.Addr() is invalid")
			}
			if got := pkt.Dst.Addr().String(); got != tt.addr {
				t.Errorf("pkt.Dst.Addr().String() = %q; want %q", got, tt.addr)
			}
		})
	}
}

func TestWithDstAddrIPv6(t *testing.T) {
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
			if !pkt.Dst.Addr().IsValid() {
				t.Fatalf("pkt.Dst.Addr() is invalid")
			}
			if got := pkt.Dst.Addr().String(); got != tt.expected {
				t.Errorf("pkt.Dst.Addr().String() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestWithInvalidAddr(t *testing.T) {
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
			if err == nil {
				t.Errorf("WithSrcAddr(%q) expected error, got nil", tt.addr)
			}
			if pkt != nil {
				t.Errorf("WithSrcAddr(%q) expected nil pkt, got %v", tt.addr, pkt)
			}

			pkt2, err := New(WithDstAddr(tt.addr))
			if err == nil {
				t.Errorf("WithDstAddr(%q) expected error, got nil", tt.addr)
			}
			if pkt2 != nil {
				t.Errorf("WithDstAddr(%q) expected nil pkt, got %v", tt.addr, pkt2)
			}
		})
	}
}

func TestWithSrcAndDstAddrPort(t *testing.T) {
	pkt := mustNewPacket(t,
		WithSrcAddrPort("10.0.0.1:12345"),
		WithDstAddrPort("[2001:db8::1]:443"),
	)
	if got := pkt.Src.String(); got != "10.0.0.1:12345" {
		t.Errorf("pkt.Src = %q; want 10.0.0.1:12345", got)
	}
	if got := pkt.Dst.String(); got != "[2001:db8::1]:443" {
		t.Errorf("pkt.Dst = %q; want [2001:db8::1]:443", got)
	}

	if _, err := New(WithSrcAddrPort("invalid")); err == nil {
		t.Error("WithSrcAddrPort(invalid) expected error, got nil")
	}
	if _, err := New(WithDstAddrPort("invalid")); err == nil {
		t.Error("WithDstAddrPort(invalid) expected error, got nil")
	}
}

func TestNewMultipleOptions(t *testing.T) {
	pkt := mustNewPacket(t,
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)

	if pkt.Proto != proto.TCP {
		t.Errorf("pkt.Proto = %v; want %v", pkt.Proto, proto.TCP)
	}
	if got := pkt.Src.Addr().String(); got != "10.0.0.1" {
		t.Errorf("pkt.Src.Addr() = %q; want 10.0.0.1", got)
	}
	if pkt.Src.Port() != 12345 {
		t.Errorf("pkt.Src.Port() = %d; want 12345", pkt.Src.Port())
	}
	if got := pkt.Dst.Addr().String(); got != "192.168.1.1" {
		t.Errorf("pkt.Dst.Addr() = %q; want 192.168.1.1", got)
	}
	if pkt.Dst.Port() != 80 {
		t.Errorf("pkt.Dst.Port() = %d; want 80", pkt.Dst.Port())
	}
}

func TestNewMultipleOptionsIPv6(t *testing.T) {
	pkt := mustNewPacket(t,
		WithProto(17),
		WithSrcAddr("2001:db8::1"),
		WithSrcPort(54321),
		WithDstAddr("cafe::1"),
		WithDstPort(443),
	)

	if pkt.Proto != proto.UDP {
		t.Errorf("pkt.Proto = %v; want %v", pkt.Proto, proto.UDP)
	}
	if got := pkt.Src.Addr().String(); got != "2001:db8::1" {
		t.Errorf("pkt.Src.Addr() = %q; want 2001:db8::1", got)
	}
	if pkt.Src.Port() != 54321 {
		t.Errorf("pkt.Src.Port() = %d; want 54321", pkt.Src.Port())
	}
	if got := pkt.Dst.Addr().String(); got != "cafe::1" {
		t.Errorf("pkt.Dst.Addr() = %q; want cafe::1", got)
	}
	if pkt.Dst.Port() != 443 {
		t.Errorf("pkt.Dst.Port() = %d; want 443", pkt.Dst.Port())
	}
}

func TestPacketStringIPv4(t *testing.T) {
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
			if got := tt.packet.String(); got != tt.expected {
				t.Errorf("packet.String() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestPacketStringIPv6(t *testing.T) {
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
			if got := tt.packet.String(); got != tt.expected {
				t.Errorf("packet.String() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestPacketStringEmptyPacket(t *testing.T) {
	pkt := mustNewPacket(t)
	result := pkt.String()
	// Empty packet will have zero netip.Addrs which are formatted as "invalid IP"
	if result != "0{invalid IP:0->invalid IP:0}" {
		t.Errorf("pkt.String() = %q; want %q", result, "0{invalid IP:0->invalid IP:0}")
	}
}

func TestPacketStringPartialPacket(t *testing.T) {
	// Only protocol
	pkt1 := mustNewPacket(t, WithProto(proto.TCP))
	if got := pkt1.String(); got != "tcp{invalid IP:0->invalid IP:0}" {
		t.Errorf("pkt1.String() = %q; want %q", got, "tcp{invalid IP:0->invalid IP:0}")
	}

	// Only ports
	pkt2 := mustNewPacket(t, WithSrcPort(1234), WithDstPort(5678))
	if got := pkt2.String(); got != "0{invalid IP:1234->invalid IP:5678}" {
		t.Errorf("pkt2.String() = %q; want %q", got, "0{invalid IP:1234->invalid IP:5678}")
	}

	// Only addresses
	pkt3 := mustNewPacket(t, WithSrcAddr("10.0.0.1"), WithDstAddr("192.168.1.1"))
	if got := pkt3.String(); got != "0{10.0.0.1:0->192.168.1.1:0}" {
		t.Errorf("pkt3.String() = %q; want %q", got, "0{10.0.0.1:0->192.168.1.1:0}")
	}
}

func TestPacketOptionsCanBeReused(t *testing.T) {
	protoOpt := WithProto(proto.TCP)
	srcPortOpt := WithSrcPort(80)
	dstPortOpt := WithDstPort(443)

	pkt1 := mustNewPacket(t, protoOpt, srcPortOpt, dstPortOpt)
	pkt2 := mustNewPacket(t, protoOpt, srcPortOpt, dstPortOpt)

	if pkt1.Proto != pkt2.Proto {
		t.Errorf("pkt1.Proto (%v) != pkt2.Proto (%v)", pkt1.Proto, pkt2.Proto)
	}
	if pkt1.Src != pkt2.Src {
		t.Errorf("pkt1.Src (%v) != pkt2.Src (%v)", pkt1.Src, pkt2.Src)
	}
	if pkt1.Dst != pkt2.Dst {
		t.Errorf("pkt1.Dst (%v) != pkt2.Dst (%v)", pkt1.Dst, pkt2.Dst)
	}
}

func TestPacketOptionsOrderIndependent(t *testing.T) {
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

	if pkt1.Proto != pkt2.Proto {
		t.Errorf("pkt1.Proto (%v) != pkt2.Proto (%v)", pkt1.Proto, pkt2.Proto)
	}
	if pkt1.Src != pkt2.Src {
		t.Errorf("pkt1.Src (%v) != pkt2.Src (%v)", pkt1.Src, pkt2.Src)
	}
	if pkt1.Dst != pkt2.Dst {
		t.Errorf("pkt1.Dst (%v) != pkt2.Dst (%v)", pkt1.Dst, pkt2.Dst)
	}
}
