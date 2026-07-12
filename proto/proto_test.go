package proto

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestProtoConstants(t *testing.T) {
	RegisterTestingT(t)

	Expect(ICMP).To(Equal(Proto(1)))
	Expect(TCP).To(Equal(Proto(6)))
	Expect(UDP).To(Equal(Proto(17)))
}

func TestProtoString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		proto    Proto
		expected string
	}{
		{ICMP, "icmp"},
		{TCP, "tcp"},
		{UDP, "udp"},
		{Proto(0), "0"},
		{Proto(7), "7"},
		{Proto(255), "255"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			Expect(tt.proto.String()).To(Equal(tt.expected))
		})
	}
}

func TestProtoParse(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		input     string
		expected  *Proto
		shouldErr bool
	}{
		{"tcp", func() *Proto { p := TCP; return &p }(), false},
		{"TCP", func() *Proto { p := TCP; return &p }(), false},
		{"udp", func() *Proto { p := UDP; return &p }(), false},
		{"UDP", func() *Proto { p := UDP; return &p }(), false},
		{"icmp", func() *Proto { p := ICMP; return &p }(), false},
		{"ICMP", func() *Proto { p := ICMP; return &p }(), false},
		{"6", func() *Proto { p := TCP; return &p }(), false},
		{"17", func() *Proto { p := UDP; return &p }(), false},
		{"1", func() *Proto { p := ICMP; return &p }(), false},
		{"0", func() *Proto { p := Proto(0); return &p }(), false},
		{"255", func() *Proto { p := Proto(255); return &p }(), false},
		{"256", nil, true},
		{"invalid", nil, true},
		{"-1", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, err := Parse(tt.input)
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
				Expect(p).To(BeNil())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(*p).To(Equal(*tt.expected))
			}
		})
	}
}
