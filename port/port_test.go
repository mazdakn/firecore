package port

import (
	"testing"
)

func TestPortResolve(t *testing.T) {
	// Numeric port: Resolve returns Number unchanged.
	if got := (Port{Number: 80}.Resolve()); got != 80 {
		t.Errorf("Port{Number: 80}.Resolve() = %d; want 80", got)
	}
	if got := (Port{Number: 0}.Resolve()); got != 0 {
		t.Errorf("Port{Number: 0}.Resolve() = %d; want 0", got)
	}
	if got := (Port{Number: 65535}.Resolve()); got != 65535 {
		t.Errorf("Port{Number: 65535}.Resolve() = %d; want 65535", got)
	}

	// Named port: Resolve looks up the number from wellKnownPorts.
	if got := (Port{Name: "http"}.Resolve()); got != 80 {
		t.Errorf("Port{Name: http}.Resolve() = %d; want 80", got)
	}
	if got := (Port{Name: "https"}.Resolve()); got != 443 {
		t.Errorf("Port{Name: https}.Resolve() = %d; want 443", got)
	}
	if got := (Port{Name: "ssh"}.Resolve()); got != 22 {
		t.Errorf("Port{Name: ssh}.Resolve() = %d; want 22", got)
	}
	if got := (Port{Name: "dns"}.Resolve()); got != 53 {
		t.Errorf("Port{Name: dns}.Resolve() = %d; want 53", got)
	}

	// Name is case-insensitive.
	if got := (Port{Name: "HTTP"}.Resolve()); got != 80 {
		t.Errorf("Port{Name: HTTP}.Resolve() = %d; want 80", got)
	}
	if got := (Port{Name: "HTTPS"}.Resolve()); got != 443 {
		t.Errorf("Port{Name: HTTPS}.Resolve() = %d; want 443", got)
	}

	// Named port with Number already set: name takes precedence.
	if got := (Port{Number: 0, Name: "http"}.Resolve()); got != 80 {
		t.Errorf("Port{Number: 0, Name: http}.Resolve() = %d; want 80", got)
	}

	// Unknown name with Number: falls back to Number.
	if got := (Port{Number: 9999, Name: "unknown"}.Resolve()); got != 9999 {
		t.Errorf("Port{Number: 9999, Name: unknown}.Resolve() = %d; want 9999", got)
	}
}

func TestPortConstants(t *testing.T) {
	if got := wellKnownPorts["http"]; got != 80 {
		t.Errorf("wellKnownPorts[http] = %d; want 80", got)
	}
	if got := wellKnownPorts["https"]; got != 443 {
		t.Errorf("wellKnownPorts[https] = %d; want 443", got)
	}
	if got := wellKnownPorts["ssh"]; got != 22 {
		t.Errorf("wellKnownPorts[ssh] = %d; want 22", got)
	}
	if got := wellKnownPorts["dns"]; got != 53 {
		t.Errorf("wellKnownPorts[dns] = %d; want 53", got)
	}
}

func TestPortString(t *testing.T) {
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
			if got := tt.port.String(); got != tt.expected {
				t.Errorf("Port.String() = %q; want %q", got, tt.expected)
			}
		})
	}
}

func TestPortIsRange(t *testing.T) {
	if got := (Port{Number: 80}.IsRange()); got != false {
		t.Errorf("Port{Number: 80}.IsRange() = %v; want false", got)
	}
	if got := (Port{Number: 80, End: 80}.IsRange()); got != false {
		t.Errorf("Port{Number: 80, End: 80}.IsRange() = %v; want false", got)
	}
	if got := (Port{Number: 80, End: 443}.IsRange()); got != true {
		t.Errorf("Port{Number: 80, End: 443}.IsRange() = %v; want true", got)
	}
	if got := (Port{Number: 0, End: 1023}.IsRange()); got != true {
		t.Errorf("Port{Number: 0, End: 1023}.IsRange() = %v; want true", got)
	}
	if got := (Port{Number: 0, End: 0}.IsRange()); got != false {
		t.Errorf("Port{Number: 0, End: 0}.IsRange() = %v; want false", got)
	}
}

func TestPortParse(t *testing.T) {
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
				if err == nil {
					t.Fatalf("Parse(%q) expected error, got nil", tt.input)
				}
				if p != nil {
					t.Fatalf("Parse(%q) expected nil port, got %+v", tt.input, p)
				}
			} else {
				if err != nil {
					t.Fatalf("Parse(%q) unexpected error: %v", tt.input, err)
				}
				if p == nil {
					t.Fatalf("Parse(%q) expected non-nil port", tt.input)
				}
				if *p != *tt.expected {
					t.Errorf("Parse(%q) = %+v; want %+v", tt.input, *p, *tt.expected)
				}
			}
		})
	}
}
