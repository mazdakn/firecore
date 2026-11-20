package set

import "net/netip"

type Type string

const (
	TypeIP     Type = "ip"
	TypePort   Type = "port"
	TypeProto  Type = "proto"
	TypeIPPort Type = "ipport"
	TypeIface  Type = "iface"
)

type Set interface {
	Add(any) error
	Match(any) bool
	Type() Type
}

// EndpointSet is implemented by sets that match a packet's source or
// destination endpoint (address, port, address:port, or interface).
// ProtoSet intentionally does not implement EndpointSet.
type EndpointSet interface {
	Set
	MatchEndpoint(ap netip.AddrPort, iface string) bool
}
