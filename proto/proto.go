package proto

import (
	"fmt"
	"strconv"
	"strings"
)

// Proto represents an IP protocol number (0–255).
// Well-known protocols can be specified by name (tcp, udp, icmp) or by number.
type Proto uint8

const (
	ICMP Proto = 1
	TCP  Proto = 6
	UDP  Proto = 17
)

// String returns the protocol name for well-known protocols, or its numeric value.
func (p Proto) String() string {
	switch p {
	case ICMP:
		return "icmp"
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	default:
		return strconv.Itoa(int(p))
	}
}

// Parse parses a protocol from a string, accepting names ("tcp", "udp", "icmp")
// or numeric values in the range 0–255. It returns nil on failure.
func Parse(s string) (*Proto, error) {
	switch strings.ToLower(s) {
	case "tcp":
		p := TCP
		return &p, nil
	case "udp":
		p := UDP
		return &p, nil
	case "icmp":
		p := ICMP
		return &p, nil
	default:
		n, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("unknown protocol: %s", s)
		}
		p := Proto(n)
		return &p, nil
	}
}
