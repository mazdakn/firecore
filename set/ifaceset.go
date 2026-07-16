package set

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// maxIfaceNameLen is the maximum length of a Linux network interface name,
// i.e. IFNAMSIZ (16) minus the trailing NUL terminator.
const maxIfaceNameLen = 15

// IfaceSet is a set of network interface name strings.
type IfaceSet struct {
	set[string]
}

// NewIfaceSet returns an empty IfaceSet.
func NewIfaceSet() *IfaceSet {
	return &IfaceSet{*New[string]()}
}

// Add inserts a value into the set. v must be a non-empty string interface
// name of at most maxIfaceNameLen bytes, containing no '/' or whitespace.
// It implements the Set interface.
func (s *IfaceSet) Add(v any) error {
	switch val := v.(type) {
	case string:
		if err := validateIfaceName(val); err != nil {
			return err
		}
		s.set.Add(val)
		return nil
	default:
		return fmt.Errorf("IfaceSet.Add: unsupported type %T", v)
	}
}

func validateIfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("IfaceSet.Add: interface name must not be empty")
	}
	if len(name) > maxIfaceNameLen {
		return fmt.Errorf("IfaceSet.Add: interface name %q exceeds %d bytes", name, maxIfaceNameLen)
	}
	if strings.ContainsRune(name, '/') {
		return fmt.Errorf("IfaceSet.Add: interface name %q must not contain '/'", name)
	}
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return fmt.Errorf("IfaceSet.Add: interface name %q must not contain whitespace", name)
	}
	return nil
}

// Match reports whether v is present in the set. v must be a string interface
// name. It implements the Set interface.
func (s *IfaceSet) Match(v any) bool {
	iface, ok := v.(string)
	if !ok {
		return false
	}
	return s.MatchIface(iface)
}

// MatchIface reports whether iface is present in the set. Unlike Match, it
// takes a concrete string rather than any, letting callers on the
// packet-matching hot path avoid interface-boxing it.
func (s *IfaceSet) MatchIface(iface string) bool {
	return s.Exists(iface)
}

func (s *IfaceSet) Type() Type {
	return TypeIface
}

// String returns a human-readable representation of the IfaceSet.
// A single-interface set renders as its name (e.g. "eth0").
// A multi-interface set renders as a sorted brace-enclosed list (e.g. "{eth0,eth1}").
func (s *IfaceSet) String() string {
	ifaces := make([]string, 0, len(s.items))
	for iface := range s.items {
		ifaces = append(ifaces, iface)
	}
	sort.Strings(ifaces)
	if len(ifaces) == 1 {
		return ifaces[0]
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, iface := range ifaces {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(iface)
	}
	sb.WriteByte('}')
	return sb.String()
}
