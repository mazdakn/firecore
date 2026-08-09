package iputil_test

import (
	"testing"

	"github.com/mazdakn/firecore/iputil"
	. "github.com/onsi/gomega"
)

func TestParseCIDROrIP(t *testing.T) {
	RegisterTestingT(t)

	t.Run("valid CIDRs", func(t *testing.T) {
		ipnet, err := iputil.ParseCIDROrIP("10.0.0.0/8")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipnet.String()).To(Equal("10.0.0.0/8"))

		ipnet6, err := iputil.ParseCIDROrIP("2001:db8::/32")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipnet6.String()).To(Equal("2001:db8::/32"))
	})

	t.Run("valid single IPs", func(t *testing.T) {
		ipnet4, err := iputil.ParseCIDROrIP("192.168.1.1")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipnet4.String()).To(Equal("192.168.1.1/32"))
		Expect(len(ipnet4.IP)).To(Equal(len(ipnet4.Mask)))

		ipnet6, err := iputil.ParseCIDROrIP("2001:db8::1")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipnet6.String()).To(Equal("2001:db8::1/128"))
		Expect(len(ipnet6.IP)).To(Equal(len(ipnet6.Mask)))
	})

	t.Run("invalid inputs", func(t *testing.T) {
		invalidInputs := []string{
			"invalid-ip",
			"256.256.256.256",
			"10.0.0.0/33",
			"not-an-ip/24",
		}
		for _, input := range invalidInputs {
			_, err := iputil.ParseCIDROrIP(input)
			Expect(err).To(HaveOccurred(), "expected error for input %q", input)
		}
	})
}
