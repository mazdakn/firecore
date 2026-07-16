package set

import (
	"fmt"
	"sort"
	"strings"

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

// Add inserts a value into the set. v must be either a proto.Proto value or a
// string protocol name/number. It implements the Set interface.
func (ps *ProtoSet) Add(v any) error {
	switch val := v.(type) {
	case proto.Proto:
		ps.set.Add(val)
		return nil
	case string:
		p, err := proto.Parse(val)
		if err != nil {
			return fmt.Errorf("invalid protocol %q: %w", val, err)
		}
		ps.set.Add(*p)
		return nil
	default:
		return fmt.Errorf("ProtoSet.Add: unsupported type %T", v)
	}
}

// Delete removes a value from the set. v accepts the same types as Add: a
// proto.Proto value or a string protocol name/number. It implements the Set
// interface.
func (ps *ProtoSet) Delete(v any) error {
	switch val := v.(type) {
	case proto.Proto:
		ps.set.Delete(val)
		return nil
	case string:
		p, err := proto.Parse(val)
		if err != nil {
			return fmt.Errorf("invalid protocol %q: %w", val, err)
		}
		ps.set.Delete(*p)
		return nil
	default:
		return fmt.Errorf("ProtoSet.Delete: unsupported type %T", v)
	}
}

// Match reports whether v is present in the set. v must be a proto.Proto
// value. It implements the Set interface.
func (ps *ProtoSet) Match(v any) bool {
	p, ok := v.(proto.Proto)
	if !ok {
		return false
	}
	return ps.Exists(p)
}

func (ps *ProtoSet) Type() Type {
	return TypeProto
}

// String returns a human-readable representation of the ProtoSet.
// A single-protocol set renders as its name or number (e.g. "tcp").
// A multi-protocol set renders as a sorted brace-enclosed list (e.g. "{tcp,udp}").
func (ps *ProtoSet) String() string {
	protos := make([]proto.Proto, 0, len(ps.items))
	for p := range ps.items {
		protos = append(protos, p)
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	if len(protos) == 1 {
		return protos[0].String()
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, p := range protos {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(p.String())
	}
	sb.WriteByte('}')
	return sb.String()
}
