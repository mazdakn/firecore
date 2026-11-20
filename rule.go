package firecore

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/set"
)

type Action int

const (
	Accept Action = iota
	Drop
	Pass
	Jump
	Return
)

// String returns the action's name, or "Undefined(n)" for an invalid value.
// Defined on a value receiver so Action satisfies fmt.Stringer for values,
// not just pointers; fmt already prints "<nil>" for a nil *Action (e.g. an
// undecided Result.Verdict) without invoking this method.
func (a Action) String() string {
	switch a {
	case Accept:
		return "Accept"
	case Drop:
		return "Drop"
	case Pass:
		return "Pass"
	case Jump:
		return "Jump"
	case Return:
		return "Return"
	default:
		return fmt.Sprintf("Undefined(%d)", a)
	}
}

func (a Action) IsTerminal() bool {
	return a == Accept || a == Drop
}

func (a Action) Validate() error {
	switch a {
	case Accept, Drop, Pass, Jump, Return:
		return nil
	default:
		return fmt.Errorf("undefined action %v", a)
	}
}

// ParseAction parses an action string into an Action type
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "accept":
		return Accept, nil
	case "drop":
		return Drop, nil
	case "pass":
		return Pass, nil
	case "jump":
		return Jump, nil
	case "return":
		return Return, nil
	default:
		return Action(0), fmt.Errorf("unknown action: %s", s)
	}
}

// endpointFilter holds the inline and named-set conditions for a single packet
// endpoint (source or destination) and polarity (positive or negated). Keeping
// inline sets separate from named sets ensures repeated inline options (e.g.
// WithSrcPort) coalesce with each other without mutating caller-owned sets
// attached via WithSrcSet/WithDstSet.
type endpointFilter struct {
	ips     *set.IPSet
	ports   *set.PortSet
	ipPorts *set.IPPortSet
	ifaces  *set.IfaceSet
	named   []set.EndpointSet
}

func (f *endpointFilter) match(ap netip.AddrPort, iface string, negate bool) bool {
	if f == nil {
		return true
	}
	if f.ips != nil && f.ips.MatchIP(ap.Addr()) == negate {
		return false
	}
	if f.ports != nil && f.ports.MatchPort(ap.Port()) == negate {
		return false
	}
	if f.ipPorts != nil && f.ipPorts.MatchIPPort(ap) == negate {
		return false
	}
	if f.ifaces != nil && f.ifaces.MatchIface(iface) == negate {
		return false
	}
	for _, s := range f.named {
		if s.MatchEndpoint(ap, iface) == negate {
			return false
		}
	}
	return true
}

func addToSet[S interface {
	comparable
	set.Set
}](slot *S, newSet func() S, val any) error {
	var zero S
	if *slot == zero {
		s := newSet()
		if err := s.Add(val); err != nil {
			return err
		}
		*slot = s
		return nil
	}
	return (*slot).Add(val)
}

type RuleOption func(*Rule) error

func (r *Rule) endpoint(dst, negate bool) *endpointFilter {
	var slot **endpointFilter
	switch {
	case !dst && !negate:
		slot = &r.src
	case !dst && negate:
		slot = &r.notSrc
	case dst && !negate:
		slot = &r.dst
	default:
		slot = &r.notDst
	}
	if *slot == nil {
		*slot = &endpointFilter{}
	}
	return *slot
}

func WithJump(chainName string) RuleOption {
	return func(r *Rule) error {
		if chainName == "" {
			return fmt.Errorf("jump target chain name must not be empty")
		}
		r.Action = Jump
		r.JumpTarget = chainName
		return nil
	}
}

func WithAction(action Action) RuleOption {
	return func(r *Rule) error {
		if err := action.Validate(); err != nil {
			return err
		}
		r.Action = action
		return nil
	}
}

func withConnState(state conntrack.State, negate bool) RuleOption {
	return func(r *Rule) error {
		parsed, err := conntrack.ParseState(string(state))
		if err != nil {
			return err
		}
		if negate {
			r.notConnStates = append(r.notConnStates, parsed)
		} else {
			r.connStates = append(r.connStates, parsed)
		}
		return nil
	}
}

func WithConnState(state conntrack.State) RuleOption {
	return withConnState(state, false)
}

func WithNotConnState(state conntrack.State) RuleOption {
	return withConnState(state, true)
}

func WithName(name string) RuleOption {
	return func(r *Rule) error {
		if name == "" {
			return fmt.Errorf("rule name must not be empty")
		}
		r.Name = name
		return nil
	}
}

func WithPayload(pattern string) RuleOption {
	return func(r *Rule) error {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid payload regex %q: %w", pattern, err)
		}
		r.payload = re
		return nil
	}
}

func WithOrder(order uint64) RuleOption {
	return func(r *Rule) error {
		r.Order = order
		return nil
	}
}

// Protocol options.

func withProto(p proto.Proto, negate bool) RuleOption {
	return func(r *Rule) error {
		slot := &r.protos
		if negate {
			slot = &r.notProtos
		}
		if err := addToSet(slot, set.NewProtoSet, p); err != nil {
			return fmt.Errorf("invalid protocol %v", p)
		}
		return nil
	}
}

func WithProto(p proto.Proto) RuleOption {
	return withProto(p, false)
}

func WithNotProto(p proto.Proto) RuleOption {
	return withProto(p, true)
}

// Named set options.

func withEndpointSet(s set.EndpointSet, dst, negate bool) RuleOption {
	return func(r *Rule) error {
		if s == nil {
			return fmt.Errorf("set must not be nil")
		}
		f := r.endpoint(dst, negate)
		f.named = append(f.named, s)
		return nil
	}
}

// WithSrcSet matches packets whose source-derived value (address, port,
// address:port, or ingress interface) is in s.
func WithSrcSet(s set.EndpointSet) RuleOption {
	return withEndpointSet(s, false, false)
}

// WithNotSrcSet matches packets whose source-derived value is not in s.
func WithNotSrcSet(s set.EndpointSet) RuleOption {
	return withEndpointSet(s, false, true)
}

// WithDstSet matches packets whose destination-derived value (address, port,
// address:port, or egress interface) is in s.
func WithDstSet(s set.EndpointSet) RuleOption {
	return withEndpointSet(s, true, false)
}

// WithNotDstSet matches packets whose destination-derived value is not in s.
func WithNotDstSet(s set.EndpointSet) RuleOption {
	return withEndpointSet(s, true, true)
}

// Source and destination port options.

func withPort(port uint16, dst, negate bool) RuleOption {
	return func(r *Rule) error {
		return addToSet(&r.endpoint(dst, negate).ports, set.NewPortSet, port)
	}
}

func WithSrcPort(port uint16) RuleOption    { return withPort(port, false, false) }
func WithNotSrcPort(port uint16) RuleOption { return withPort(port, false, true) }
func WithDstPort(port uint16) RuleOption    { return withPort(port, true, false) }
func WithNotDstPort(port uint16) RuleOption { return withPort(port, true, true) }

// Source and destination address options.

func withNet(cidr string, dst, negate bool) RuleOption {
	return func(r *Rule) error {
		return addToSet(&r.endpoint(dst, negate).ips, set.NewIPSet, cidr)
	}
}

func WithSrcNet(cidr string) RuleOption    { return withNet(cidr, false, false) }
func WithNotSrcNet(cidr string) RuleOption { return withNet(cidr, false, true) }
func WithDstNet(cidr string) RuleOption    { return withNet(cidr, true, false) }
func WithNotDstNet(cidr string) RuleOption { return withNet(cidr, true, true) }

// Source and destination address:port options.

func withAddrPort(addrPort string, dst, negate bool) RuleOption {
	return func(r *Rule) error {
		return addToSet(&r.endpoint(dst, negate).ipPorts, set.NewIPPortSet, addrPort)
	}
}

func WithSrcAddrPort(addrPort string) RuleOption    { return withAddrPort(addrPort, false, false) }
func WithNotSrcAddrPort(addrPort string) RuleOption { return withAddrPort(addrPort, false, true) }
func WithDstAddrPort(addrPort string) RuleOption    { return withAddrPort(addrPort, true, false) }
func WithNotDstAddrPort(addrPort string) RuleOption { return withAddrPort(addrPort, true, true) }

// Source and destination interface options.

func withIface(iface string, dst, negate bool) RuleOption {
	return func(r *Rule) error {
		return addToSet(&r.endpoint(dst, negate).ifaces, set.NewIfaceSet, iface)
	}
}

func WithSrcIface(iface string) RuleOption    { return withIface(iface, false, false) }
func WithNotSrcIface(iface string) RuleOption { return withIface(iface, false, true) }
func WithDstIface(iface string) RuleOption    { return withIface(iface, true, false) }
func WithNotDstIface(iface string) RuleOption { return withIface(iface, true, true) }

func NewRule(opts ...RuleOption) (*Rule, error) {
	var r Rule
	for _, o := range opts {
		if o == nil {
			return nil, fmt.Errorf("rule option must not be nil")
		}
		if err := o(&r); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

type Rule struct {
	Name       string
	Order      uint64
	Action     Action
	JumpTarget string // name of the chain to jump to when Action == Jump

	protos        *set.ProtoSet
	notProtos     *set.ProtoSet
	src           *endpointFilter
	notSrc        *endpointFilter
	dst           *endpointFilter
	notDst        *endpointFilter
	connStates    []conntrack.State
	notConnStates []conntrack.State
	payload       *regexp.Regexp

	packetCount atomic.Uint64
	byteCount   atomic.Uint64
}

func (r *Rule) Match(pkt *packet.Packet) bool {
	return r.MatchWithConntrackState(pkt, conntrack.StateNew)
}

func (r *Rule) MatchWithConntrackState(pkt *packet.Packet, state conntrack.State) bool {
	if pkt == nil {
		return false
	}
	if state == "" {
		state = conntrack.StateNew
	}
	if r.protos != nil && !r.protos.MatchProto(pkt.Proto) {
		return false
	}
	if r.notProtos != nil && r.notProtos.MatchProto(pkt.Proto) {
		return false
	}
	if !r.src.match(pkt.Src, pkt.Metadata.IngressIface, false) {
		return false
	}
	if !r.notSrc.match(pkt.Src, pkt.Metadata.IngressIface, true) {
		return false
	}
	if !r.dst.match(pkt.Dst, pkt.Metadata.EgressIface, false) {
		return false
	}
	if !r.notDst.match(pkt.Dst, pkt.Metadata.EgressIface, true) {
		return false
	}
	if len(r.connStates) > 0 && !slices.Contains(r.connStates, state) {
		return false
	}
	if len(r.notConnStates) > 0 && slices.Contains(r.notConnStates, state) {
		return false
	}
	if r.payload != nil && !r.payload.Match(pkt.Payload) {
		return false
	}
	// All conditions passed - increment packet and byte counters
	r.packetCount.Add(1)
	r.byteCount.Add(uint64(pkt.Size))
	return true
}

func (r *Rule) PacketCount() uint64 {
	return r.packetCount.Load()
}

func (r *Rule) IncrementPacketCount() {
	r.packetCount.Add(1)
}

func (r *Rule) ResetPacketCount() {
	r.packetCount.Store(0)
}

func (r *Rule) ByteCount() uint64 {
	return r.byteCount.Load()
}

func (r *Rule) AddByteCount(n uint64) {
	r.byteCount.Add(n)
}

func (r *Rule) ResetByteCount() {
	r.byteCount.Store(0)
}
