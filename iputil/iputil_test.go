package iputil_test

import (
	"testing"

	"github.com/mazdakn/firecore/iputil"
)

func TestParseCIDROrIP(t *testing.T) {
	t.Run("valid CIDRs", func(t *testing.T) {
		ipnet, err := iputil.ParseCIDROrIP("10.0.0.0/8")
		if err != nil {
			t.Fatalf("ParseCIDROrIP(10.0.0.0/8) unexpected error: %v", err)
		}
		if got := ipnet.String(); got != "10.0.0.0/8" {
			t.Errorf("ipnet.String() = %q; want 10.0.0.0/8", got)
		}

		ipnet6, err := iputil.ParseCIDROrIP("2001:db8::/32")
		if err != nil {
			t.Fatalf("ParseCIDROrIP(2001:db8::/32) unexpected error: %v", err)
		}
		if got := ipnet6.String(); got != "2001:db8::/32" {
			t.Errorf("ipnet6.String() = %q; want 2001:db8::/32", got)
		}
	})

	t.Run("valid single IPs", func(t *testing.T) {
		ipnet4, err := iputil.ParseCIDROrIP("192.168.1.1")
		if err != nil {
			t.Fatalf("ParseCIDROrIP(192.168.1.1) unexpected error: %v", err)
		}
		if got := ipnet4.String(); got != "192.168.1.1/32" {
			t.Errorf("ipnet4.String() = %q; want 192.168.1.1/32", got)
		}
		if len(ipnet4.IP) != len(ipnet4.Mask) {
			t.Errorf("len(ipnet4.IP) = %d != len(ipnet4.Mask) = %d", len(ipnet4.IP), len(ipnet4.Mask))
		}

		ipnet6, err := iputil.ParseCIDROrIP("2001:db8::1")
		if err != nil {
			t.Fatalf("ParseCIDROrIP(2001:db8::1) unexpected error: %v", err)
		}
		if got := ipnet6.String(); got != "2001:db8::1/128" {
			t.Errorf("ipnet6.String() = %q; want 2001:db8::1/128", got)
		}
		if len(ipnet6.IP) != len(ipnet6.Mask) {
			t.Errorf("len(ipnet6.IP) = %d != len(ipnet6.Mask) = %d", len(ipnet6.IP), len(ipnet6.Mask))
		}
	})

	t.Run("invalid inputs", func(t *testing.T) {
		invalidInputs := []string{
			"invalid-ip",
			"256.256.256.256",
			"10.0.0.0/33",
			"not-an-ip/24",
		}
		for _, input := range invalidInputs {
			if _, err := iputil.ParseCIDROrIP(input); err == nil {
				t.Errorf("expected error for input %q, got nil", input)
			}
		}
	})
}
