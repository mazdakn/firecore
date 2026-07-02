package set

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
