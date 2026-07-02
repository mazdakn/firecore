package conntrack

import (
	"fmt"
	"strings"

	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
)

type State string

const (
	StateNew         State = "new"
	StateEstablished State = "established"
)

func (s State) String() string {
	return string(s)
}

func ParseState(raw string) (State, error) {
	switch strings.ToLower(raw) {
	case string(StateNew):
		return StateNew, nil
	case string(StateEstablished):
		return StateEstablished, nil
	default:
		return "", fmt.Errorf("unknown conntrack state: %s", raw)
	}
}

type key struct {
	Proto   proto.Proto
	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
}

type Tracker struct {
	entries map[key]State
}

func NewTracker() *Tracker {
	return &Tracker{
		entries: map[key]State{},
	}
}

func (t *Tracker) Lookup(pkt *packet.Packet) State {
	if pkt == nil {
		panic("conntrack.Lookup: nil packet")
	}
	if state, ok := t.entries[keyFromPacket(pkt)]; ok {
		return state
	}
	return StateNew
}

func (t *Tracker) CommitAccepted(pkt *packet.Packet) {
	if pkt == nil {
		panic("conntrack.CommitAccepted: nil packet")
	}
	forward := keyFromPacket(pkt)
	reverse := reverseKeyFromPacket(pkt)
	t.entries[forward] = StateEstablished
	t.entries[reverse] = StateEstablished
}

func keyFromPacket(pkt *packet.Packet) key {
	return key{
		Proto:   pkt.Proto,
		SrcAddr: pkt.SrcAddr.String(),
		SrcPort: pkt.SrcPort,
		DstAddr: pkt.DstAddr.String(),
		DstPort: pkt.DstPort,
	}
}

func reverseKeyFromPacket(pkt *packet.Packet) key {
	return key{
		Proto:   pkt.Proto,
		SrcAddr: pkt.DstAddr.String(),
		SrcPort: pkt.DstPort,
		DstAddr: pkt.SrcAddr.String(),
		DstPort: pkt.SrcPort,
	}
}
