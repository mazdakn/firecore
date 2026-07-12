package port

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestPortResolve(t *testing.T) {
	RegisterTestingT(t)

	// Numeric port: Resolve returns Number unchanged.
	Expect(Port{Number: 80}.Resolve()).To(Equal(uint16(80)))
	Expect(Port{Number: 0}.Resolve()).To(Equal(uint16(0)))
	Expect(Port{Number: 65535}.Resolve()).To(Equal(uint16(65535)))

	// Named port: Resolve looks up the number from wellKnownPorts.
	Expect(Port{Name: "http"}.Resolve()).To(Equal(uint16(80)))
	Expect(Port{Name: "https"}.Resolve()).To(Equal(uint16(443)))
	Expect(Port{Name: "ssh"}.Resolve()).To(Equal(uint16(22)))
	Expect(Port{Name: "dns"}.Resolve()).To(Equal(uint16(53)))

	// Name is case-insensitive.
	Expect(Port{Name: "HTTP"}.Resolve()).To(Equal(uint16(80)))
	Expect(Port{Name: "HTTPS"}.Resolve()).To(Equal(uint16(443)))

	// Named port with Number already set: name takes precedence.
	Expect(Port{Number: 0, Name: "http"}.Resolve()).To(Equal(uint16(80)))

	// Unknown name with Number: falls back to Number.
	Expect(Port{Number: 9999, Name: "unknown"}.Resolve()).To(Equal(uint16(9999)))
}

func TestPortConstants(t *testing.T) {
	RegisterTestingT(t)

	Expect(wellKnownPorts["http"]).To(Equal(uint16(80)))
	Expect(wellKnownPorts["https"]).To(Equal(uint16(443)))
	Expect(wellKnownPorts["ssh"]).To(Equal(uint16(22)))
	Expect(wellKnownPorts["dns"]).To(Equal(uint16(53)))
}

func TestPortString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		port     Port
		expected string
	}{
		{Port{Number: 80, Name: "http"}, "http"},
		{Port{Number: 443, Name: "https"}, "https"},
		{Port{Number: 80}, "80"},
		{Port{Number: 0}, "0"},
		{Port{Number: 65535}, "65535"},
		// Ranges.
		{Port{Number: 1024, End: 65535}, "1024-65535"},
		{Port{Number: 0, End: 1023}, "0-1023"},
		{Port{Number: 80, End: 443}, "80-443"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			Expect(tt.port.String()).To(Equal(tt.expected))
		})
	}
}

func TestPortIsRange(t *testing.T) {
	RegisterTestingT(t)

	Expect(Port{Number: 80}.IsRange()).To(BeFalse())
	Expect(Port{Number: 80, End: 80}.IsRange()).To(BeFalse())
	Expect(Port{Number: 80, End: 443}.IsRange()).To(BeTrue())
	Expect(Port{Number: 0, End: 1023}.IsRange()).To(BeTrue())
	Expect(Port{Number: 0, End: 0}.IsRange()).To(BeFalse())
}

func TestPortParse(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		input     string
		expected  *Port
		shouldErr bool
	}{
		{"http", &Port{Number: 80, Name: "http"}, false},
		{"HTTP", &Port{Number: 80, Name: "http"}, false},
		{"https", &Port{Number: 443, Name: "https"}, false},
		{"ssh", &Port{Number: 22, Name: "ssh"}, false},
		{"dns", &Port{Number: 53, Name: "dns"}, false},
		{"ftp", &Port{Number: 21, Name: "ftp"}, false},
		{"smtp", &Port{Number: 25, Name: "smtp"}, false},
		{"80", &Port{Number: 80}, false},
		{"443", &Port{Number: 443}, false},
		{"0", &Port{Number: 0}, false},
		{"65535", &Port{Number: 65535}, false},
		// Port ranges.
		{"1024-65535", &Port{Number: 1024, End: 65535}, false},
		{"0-1023", &Port{Number: 0, End: 1023}, false},
		{"80-443", &Port{Number: 80, End: 443}, false},
		{"8080-8090", &Port{Number: 8080, End: 8090}, false},
		// Error cases.
		{"65536", nil, true},
		{"invalid", nil, true},
		{"-1", nil, true},
		{"443-80", nil, true},   // end < start
		{"abc-443", nil, true},  // invalid start
		{"80-xyz", nil, true},   // invalid end
		{"80-65536", nil, true}, // end out of range
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
