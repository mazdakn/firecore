package set

import (
	"testing"

	"github.com/mazdakn/firecore/port"
)

func TestPortSetAddPortStruct(t *testing.T) {
	ps := NewPortSet()

	// port.Port with only a name — number must be resolved from the name.
	if err := ps.Add(port.Port{Name: "http"}); err != nil {
		t.Fatalf("ps.Add(http) unexpected error: %v", err)
	}
	if !ps.Match(uint16(80)) {
		t.Errorf("expected match for 80")
	}
	if ps.Match(uint16(443)) {
		t.Errorf("expected no match for 443")
	}

	if err := ps.Add(port.Port{Name: "https"}); err != nil {
		t.Fatalf("ps.Add(https) unexpected error: %v", err)
	}
	if !ps.Match(uint16(443)) {
		t.Errorf("expected match for 443")
	}

	// port.Port with both number and name — name takes precedence.
	ps2 := NewPortSet()
	if err := ps2.Add(port.Port{Number: 0, Name: "ssh"}); err != nil {
		t.Fatalf("ps2.Add(ssh) unexpected error: %v", err)
	}
	if !ps2.Match(uint16(22)) {
		t.Errorf("expected match for 22")
	}

	// port.Port with only a number.
	ps3 := NewPortSet()
	if err := ps3.Add(port.Port{Number: 8080}); err != nil {
		t.Fatalf("ps3.Add(8080) unexpected error: %v", err)
	}
	if !ps3.Match(uint16(8080)) {
		t.Errorf("expected match for 8080")
	}
}

func TestPortSetAdd(t *testing.T) {
	ps := NewPortSet()

	err := ps.Add(uint16(80))
	if err != nil {
		t.Fatalf("ps.Add(80) unexpected error: %v", err)
	}
	if !ps.Match(uint16(80)) {
		t.Errorf("expected match for 80")
	}
	if ps.Match(uint16(443)) {
		t.Errorf("expected no match for 443")
	}
}

func TestPortSetDelete(t *testing.T) {
	ps := NewPortSet()

	err := ps.Add(uint16(80))
	if err != nil {
		t.Fatalf("ps.Add(80) unexpected error: %v", err)
	}
	err = ps.Add(uint16(443))
	if err != nil {
		t.Fatalf("ps.Add(443) unexpected error: %v", err)
	}
	if !ps.Match(uint16(80)) {
		t.Errorf("expected match for 80")
	}

	if err := ps.Delete(uint16(80)); err != nil {
		t.Fatalf("ps.Delete(80) unexpected error: %v", err)
	}
	if ps.Match(uint16(80)) {
		t.Errorf("expected no match for 80 after delete")
	}
	if !ps.Match(uint16(443)) {
		t.Errorf("expected match for 443")
	}
}

func TestPortSetDeleteRange(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add(uint16(80)); err != nil {
		t.Fatalf("ps.Add(80) unexpected error: %v", err)
	}
	if err := ps.Add("1024-65535"); err != nil {
		t.Fatalf("ps.Add(1024-65535) unexpected error: %v", err)
	}
	if !ps.Match(uint16(8080)) {
		t.Errorf("expected match for 8080")
	}

	if err := ps.Delete(port.Port{Number: 1024, End: 65535}); err != nil {
		t.Fatalf("ps.Delete unexpected error: %v", err)
	}
	if ps.Match(uint16(8080)) {
		t.Errorf("expected no match for 8080 after delete")
	}
	if !ps.Match(uint16(80)) {
		t.Errorf("expected match for 80")
	}
}

func TestPortSetDeleteRangeString(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add("1024-65535"); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if !ps.Match(uint16(8080)) {
		t.Errorf("expected match for 8080")
	}

	if err := ps.Delete("1024-65535"); err != nil {
		t.Fatalf("ps.Delete unexpected error: %v", err)
	}
	if ps.Match(uint16(8080)) {
		t.Errorf("expected no match for 8080 after delete")
	}
}

func TestPortSetDeleteUnsupportedType(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Delete(3.14); err == nil {
		t.Fatal("ps.Delete(3.14) expected error, got nil")
	}
}

func TestPortSetDeleteMissing(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add(uint16(80)); err != nil {
		t.Fatalf("ps.Add(80) unexpected error: %v", err)
	}

	// Deleting a value that was never added is a no-op, not an error.
	if err := ps.Delete(uint16(443)); err != nil {
		t.Fatalf("ps.Delete(443) unexpected error: %v", err)
	}
	if !ps.Match(uint16(80)) {
		t.Errorf("expected match for 80")
	}
}

func TestPortSetMatch(t *testing.T) {
	ps := NewPortSet()

	if ps.Match(uint16(80)) {
		t.Errorf("expected no match on empty set")
	}

	err := ps.Add(uint16(80))
	if err != nil {
		t.Fatalf("ps.Add(80) unexpected error: %v", err)
	}
	if !ps.Match(uint16(80)) {
		t.Errorf("expected match for 80")
	}
	if ps.Match(uint16(8080)) {
		t.Errorf("expected no match for 8080")
	}
}

func TestPortSetStringOnePort(t *testing.T) {
	ps := NewPortSet()
	err := ps.Add(uint16(80))
	if err != nil {
		t.Fatalf("ps.Add(80) unexpected error: %v", err)
	}
	if got := ps.String(); got != "80" {
		t.Errorf("ps.String() = %q; want 80", got)
	}
}

func TestPortSetStringMultiplePorts(t *testing.T) {
	ps := NewPortSet()
	err := ps.Add(uint16(443))
	if err != nil {
		t.Fatalf("ps.Add(443) unexpected error: %v", err)
	}
	err = ps.Add(uint16(80))
	if err != nil {
		t.Fatalf("ps.Add(80) unexpected error: %v", err)
	}
	if got := ps.String(); got != "{80,443}" {
		t.Errorf("ps.String() = %q; want {80,443}", got)
	}
}

func TestPortSetAddRange(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add(port.Port{Number: 1024, End: 65535}); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if !ps.Match(uint16(1024)) {
		t.Errorf("expected match for 1024")
	}
	if !ps.Match(uint16(8080)) {
		t.Errorf("expected match for 8080")
	}
	if !ps.Match(uint16(65535)) {
		t.Errorf("expected match for 65535")
	}
	if ps.Match(uint16(1023)) {
		t.Errorf("expected no match for 1023")
	}
	if ps.Match(uint16(80)) {
		t.Errorf("expected no match for 80")
	}
}

func TestPortSetAddInvertedRangeFails(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add(port.Port{Number: 100, End: 50}); err == nil {
		t.Fatal("ps.Add inverted range expected error, got nil")
	}
	if ps.Match(uint16(100)) {
		t.Errorf("expected no match for 100")
	}
	if ps.Match(uint16(75)) {
		t.Errorf("expected no match for 75")
	}
	if ps.Match(uint16(50)) {
		t.Errorf("expected no match for 50")
	}
}

func TestPortSetAddRangeString(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add("1024-65535"); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if !ps.Match(uint16(1024)) {
		t.Errorf("expected match for 1024")
	}
	if !ps.Match(uint16(8080)) {
		t.Errorf("expected match for 8080")
	}
	if !ps.Match(uint16(65535)) {
		t.Errorf("expected match for 65535")
	}
	if ps.Match(uint16(1023)) {
		t.Errorf("expected no match for 1023")
	}
}

func TestPortSetAddRangeAndSinglePort(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add(uint16(80)); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if err := ps.Add("1024-65535"); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if !ps.Match(uint16(80)) {
		t.Errorf("expected match for 80")
	}
	if !ps.Match(uint16(8080)) {
		t.Errorf("expected match for 8080")
	}
	if ps.Match(uint16(443)) {
		t.Errorf("expected no match for 443")
	}
}

func TestPortSetStringWithRange(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add("1024-65535"); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if got := ps.String(); got != "1024-65535" {
		t.Errorf("ps.String() = %q; want 1024-65535", got)
	}
}

func TestPortSetStringWithRangeAndPort(t *testing.T) {
	ps := NewPortSet()
	if err := ps.Add(uint16(80)); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if err := ps.Add("1024-65535"); err != nil {
		t.Fatalf("ps.Add unexpected error: %v", err)
	}
	if got := ps.String(); got != "{80,1024-65535}" {
		t.Errorf("ps.String() = %q; want {80,1024-65535}", got)
	}
}
