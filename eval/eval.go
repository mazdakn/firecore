package eval

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/rule"
)

type Context struct {
	Packet    *packet.Packet
	ConnState *conntrack.State
}

func New(pkt *packet.Packet) *Context {
	return &Context{Packet: pkt}
}

type Result struct {
	Verdict *rule.Action
	Trace   []*rule.Rule
}
