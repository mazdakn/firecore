package set

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mazdakn/firecore/port"
)

// portRange represents an inclusive range of port numbers [start, end].
type portRange struct {
	start, end uint16
}

// PortSet is a set of uint16 port values and port ranges.
type PortSet struct {
	set[uint16]
	ranges []portRange
}

// NewPortSet returns an empty PortSet.
func NewPortSet() *PortSet {
	return &PortSet{*New[uint16](), nil}
}

// Add inserts a value into the set. v must be a uint16 port number, a port.Port
// (optionally representing a range), or a string representation of a port
// number, well-known port name (e.g. "http"), or port range (e.g. "1024-65535").
// It implements the Set interface.
func (p *PortSet) Add(v any) error {
	switch val := v.(type) {
	case uint16:
		p.set.Add(val)
		return nil
	case port.Port:
		if val.End != 0 && val.End < val.Number {
			return fmt.Errorf("invalid port range: end %d must be >= start %d", val.End, val.Number)
		}
		if val.IsRange() {
			p.ranges = append(p.ranges, portRange{val.Number, val.End})
		} else {
			p.set.Add(val.Resolve())
		}
		return nil
	case string:
		parsed, err := port.Parse(val)
		if err != nil {
			return fmt.Errorf("invalid port %q: %w", val, err)
		}
		if parsed.IsRange() {
			p.ranges = append(p.ranges, portRange{parsed.Number, parsed.End})
		} else {
			p.set.Add(parsed.Number)
		}
		return nil
	default:
		return fmt.Errorf("PortSet.Add: unsupported type %T", v)
	}
}

// Delete removes a value from the set. v accepts the same types as Add: a
// uint16 port number, a port.Port (optionally representing a range), or a
// string representation of a port number, well-known port name (e.g. "http"),
// or port range (e.g. "1024-65535"). It implements the Set interface.
func (p *PortSet) Delete(v any) error {
	switch val := v.(type) {
	case uint16:
		p.set.Delete(val)
		return nil
	case port.Port:
		if val.End != 0 && val.End < val.Number {
			return fmt.Errorf("invalid port range: end %d must be >= start %d", val.End, val.Number)
		}
		if val.IsRange() {
			p.deleteRange(val.Number, val.End)
		} else {
			p.set.Delete(val.Resolve())
		}
		return nil
	case string:
		parsed, err := port.Parse(val)
		if err != nil {
			return fmt.Errorf("invalid port %q: %w", val, err)
		}
		if parsed.IsRange() {
			p.deleteRange(parsed.Number, parsed.End)
		} else {
			p.set.Delete(parsed.Number)
		}
		return nil
	default:
		return fmt.Errorf("PortSet.Delete: unsupported type %T", v)
	}
}

// deleteRange removes the [start, end] range from p.ranges, if present.
func (p *PortSet) deleteRange(start, end uint16) {
	for i, r := range p.ranges {
		if r.start == start && r.end == end {
			p.ranges = append(p.ranges[:i], p.ranges[i+1:]...)
			return
		}
	}
}

// Match reports whether v is present in the set or falls within any stored
// range. v must be a uint16 port number. It implements the Set interface.
func (p *PortSet) Match(v any) bool {
	portNum, ok := v.(uint16)
	if !ok {
		return false
	}
	return p.MatchPort(portNum)
}

// MatchPort reports whether port is present in the set or falls within any
// stored range. Unlike Match, it takes a concrete uint16 rather than any,
// letting callers on the packet-matching hot path avoid interface-boxing it.
func (p *PortSet) MatchPort(port uint16) bool {
	if p.Exists(port) {
		return true
	}
	for _, r := range p.ranges {
		if port >= r.start && port <= r.end {
			return true
		}
	}
	return false
}

func (p *PortSet) Type() Type {
	return TypePort
}

// String returns a human-readable representation of the PortSet.
// A single-entry set renders as its number or range (e.g. "80" or "1024-65535").
// A multi-entry set renders as a sorted brace-enclosed list (e.g. "{80,443}").
func (p *PortSet) String() string {
	ports := make([]uint16, 0, len(p.items))
	for port := range p.items {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })

	sorted := make([]portRange, len(p.ranges))
	copy(sorted, p.ranges)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].start != sorted[j].start {
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].end < sorted[j].end
	})

	// Build a merged sorted list by interleaving individual ports (as
	// single-element ranges) with the stored ranges, ordering by start value.
	entries := make([]portRange, 0, len(ports)+len(sorted))
	for _, port := range ports {
		entries = append(entries, portRange{port, port})
	}
	entries = append(entries, sorted...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].start != entries[j].start {
			return entries[i].start < entries[j].start
		}
		return entries[i].end < entries[j].end
	})

	if len(entries) == 1 {
		e := entries[0]
		if e.start == e.end {
			return strconv.Itoa(int(e.start))
		}
		return strconv.Itoa(int(e.start)) + "-" + strconv.Itoa(int(e.end))
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			sb.WriteByte(',')
		}
		if e.start == e.end {
			sb.WriteString(strconv.Itoa(int(e.start)))
		} else {
			sb.WriteString(strconv.Itoa(int(e.start)))
			sb.WriteByte('-')
			sb.WriteString(strconv.Itoa(int(e.end)))
		}
	}
	sb.WriteByte('}')
	return sb.String()
}
