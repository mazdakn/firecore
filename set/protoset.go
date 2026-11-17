package set

import (
	"fmt"
	"slices"

	"github.com/mazdakn/firecore/proto"
)

// ProtoSet is a set of Proto protocol values.
type ProtoSet struct {
	set[proto.Proto]
}

// NewProtoSet returns an empty ProtoSet.
func NewProtoSet() *ProtoSet {
	return &ProtoSet{*New[proto.Proto]()}
}

func toProto(op string, v any) (proto.Proto, error) {
	switch val := v.(type) {
	case proto.Proto:
		return val, nil
	case string:
		p, err := proto.Parse(val)
		if err != nil {
			return 0, fmt.Errorf("invalid protocol %q: %w", val, err)
		}
		return *p, nil
	default:
		return 0, fmt.Errorf("%s: unsupported type %T", op, v)
	}
}

// Add inserts a value into the set. v must be either a proto.Proto value or a
// string protocol name/number. It implements the Set interface.
func (ps *ProtoSet) Add(v any) error {
	p, err := toProto("ProtoSet.Add", v)
	if err != nil {
		return err
	}
	ps.set.Add(p)
	return nil
}

// Delete removes a value from the set. v accepts the same types as Add: a
// proto.Proto value or a string protocol name/number. It implements the Set
// interface.
func (ps *ProtoSet) Delete(v any) error {
	p, err := toProto("ProtoSet.Delete", v)
	if err != nil {
		return err
	}
	ps.set.Delete(p)
	return nil
}

// Match reports whether v is present in the set. v must be a proto.Proto
// value. It implements the Set interface.
func (ps *ProtoSet) Match(v any) bool {
	p, ok := v.(proto.Proto)
	if !ok {
		return false
	}
	return ps.MatchProto(p)
}

// MatchProto reports whether p is present in the set. Unlike Match, it takes
// a concrete proto.Proto rather than any, letting callers on the
// packet-matching hot path avoid interface-boxing it.
func (ps *ProtoSet) MatchProto(p proto.Proto) bool {
	return ps.Exists(p)
}

func (ps *ProtoSet) Type() Type {
	return TypeProto
}

// String returns a human-readable representation of the ProtoSet.
// A single-protocol set renders as its name or number (e.g. "tcp").
// A multi-protocol set renders as a sorted brace-enclosed list (e.g. "{tcp,udp}").
func (ps *ProtoSet) String() string {
	protos := ps.keys()
	slices.Sort(protos)
	return formatStringers(protos)
}
