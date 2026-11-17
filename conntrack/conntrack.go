package conntrack

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

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
	Proto proto.Proto
	Src   netip.AddrPort
	Dst   netip.AddrPort
}

type Tracker struct {
	mu      sync.RWMutex
	entries map[key]State
}

func NewTracker() *Tracker {
	return &Tracker{
		entries: map[key]State{},
	}
}

func (t *Tracker) Lookup(pkt *packet.Packet) (State, error) {
	if pkt == nil {
		return "", fmt.Errorf("conntrack.Lookup: nil packet")
	}
	k := keyFromPacket(pkt)
	t.mu.RLock()
	state, ok := t.entries[k]
	t.mu.RUnlock()
	if ok {
		return state, nil
	}
	return StateNew, nil
}

func (t *Tracker) CommitAccepted(pkt *packet.Packet) error {
	if pkt == nil {
		return fmt.Errorf("conntrack.CommitAccepted: nil packet")
	}
	forward := keyFromPacket(pkt)
	reverse := reverseKeyFromPacket(pkt)
	t.mu.Lock()
	t.entries[forward] = StateEstablished
	t.entries[reverse] = StateEstablished
	t.mu.Unlock()
	return nil
}

func keyFromPacket(pkt *packet.Packet) key {
	return key{
		Proto: pkt.Proto,
		Src:   pkt.Src,
		Dst:   pkt.Dst,
	}
}

func reverseKeyFromPacket(pkt *packet.Packet) key {
	return key{
		Proto: pkt.Proto,
		Src:   pkt.Dst,
		Dst:   pkt.Src,
	}
}
