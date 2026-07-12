package port

import (
	"fmt"
	"strconv"
	"strings"
)

// Port represents a network port or port range. Number holds the port number
// (or the start of a range). End is the inclusive end of the range; when End
// is greater than Number the port represents the range [Number, End]. Name is
// set when the port was specified by a well-known service name and is used for
// display purposes.
type Port struct {
	Number uint16
	End    uint16
	Name   string
}

// IsRange reports whether the port represents a range of ports.
func (p Port) IsRange() bool {
	return p.End > p.Number
}

// wellKnownPorts maps common service names to their assigned port numbers.
var wellKnownPorts = map[string]uint16{
	"ftp":        21,
	"ssh":        22,
	"telnet":     23,
	"smtp":       25,
	"dns":        53,
	"http":       80,
	"pop3":       110,
	"imap":       143,
	"ldap":       389,
	"https":      443,
	"smb":        445,
	"mysql":      3306,
	"rdp":        3389,
	"postgresql": 5432,
	"redis":      6379,
	"mongodb":    27017,
}

// Parse parses a port from a string, accepting well-known service names (e.g.
// "http"), numeric values in the range 0–65535, or port ranges in the form
// "start-end" (e.g. "1024-65535").
func Parse(s string) (*Port, error) {
	// Check for range syntax: "start-end".
	if idx := strings.Index(s, "-"); idx > 0 {
		startStr := s[:idx]
		endStr := s[idx+1:]
		start, err := strconv.ParseUint(startStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port range start %q in %q", startStr, s)
		}
		end, err := strconv.ParseUint(endStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port range end %q in %q", endStr, s)
		}
		if end < start {
			return nil, fmt.Errorf("port range end %d must be >= start %d", end, start)
		}
		return &Port{Number: uint16(start), End: uint16(end)}, nil
	}

	lower := strings.ToLower(s)
	if n, ok := wellKnownPorts[lower]; ok {
		return &Port{Number: n, Name: lower}, nil
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("unknown port: %s", s)
	}
	return &Port{Number: uint16(n)}, nil
}

// Resolve returns the port number. When the Port was created with a name,
// it looks the number up in the well-known ports map. When no name is set,
// it returns Number directly. If the Name is set but not in the well-known
// ports map, it falls back to Number; this can only happen if a Port is
// built directly with a Name that Parse would never produce, since Parse
// only sets Name when it matches an entry in wellKnownPorts.
func (p Port) Resolve() uint16 {
	if p.Name != "" {
		if n, ok := wellKnownPorts[strings.ToLower(p.Name)]; ok {
			return n
		}
	}
	return p.Number
}

// String returns the port name if the port was specified by name, a range
// "start-end" for port ranges, or the numeric value as a string otherwise.
func (p Port) String() string {
	if p.Name != "" {
		return p.Name
	}
	if p.IsRange() {
		return strconv.Itoa(int(p.Number)) + "-" + strconv.Itoa(int(p.End))
	}
	return strconv.Itoa(int(p.Number))
}
