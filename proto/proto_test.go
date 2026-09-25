package proto

import (
	"testing"
)

func TestProtoConstants(t *testing.T) {
	if got := ICMP; got != Proto(1) {
		t.Errorf("ICMP = %d; want 1", got)
	}
	if got := TCP; got != Proto(6) {
		t.Errorf("TCP = %d; want 6", got)
	}
	if got := UDP; got != Proto(17) {
		t.Errorf("UDP = %d; want 17", got)
	}
}

func TestProtoString(t *testing.T) {
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
			if got := tt.proto.String(); got != tt.expected {
				t.Errorf("Proto.String() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestProtoParse(t *testing.T) {
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
				if err == nil {
					t.Fatalf("Parse(%q) expected error, got nil", tt.input)
				}
				if p != nil {
					t.Fatalf("Parse(%q) expected nil proto, got %+v", tt.input, p)
				}
			} else {
				if err != nil {
					t.Fatalf("Parse(%q) unexpected error: %v", tt.input, err)
				}
				if p == nil {
					t.Fatalf("Parse(%q) expected non-nil proto", tt.input)
				}
				if *p != *tt.expected {
					t.Errorf("Parse(%q) = %+v; want %+v", tt.input, *p, *tt.expected)
				}
			}
		})
	}
}
