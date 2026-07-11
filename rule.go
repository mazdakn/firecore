package firecore

import (
	"fmt"
	"net"
	"strings"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/counter"
	"github.com/mazdakn/firecore/matcher"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/payload"
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
// undecided eval.Result.Verdict) without invoking this method.
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

type RuleOption func(*Rule) error

// findMatcher returns the first matcher in r.Matchers of concrete type M,
// so RuleOptions that extend an existing condition (e.g. repeated
// WithSrcPort calls) can reuse it instead of adding a redundant Matcher.
func findMatcher[M matcher.Matcher](r *Rule) (M, bool) {
	for _, m := range r.Matchers {
		if match, ok := m.(M); ok {
			return match, true
		}
	}
	var zero M
	return zero, false
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

func WithConnState(state conntrack.State) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.ConnStateMatcher](r)
		if !ok {
			m = &matcher.ConnStateMatcher{}
			r.Matchers = append(r.Matchers, m)
		}
		m.States = append(m.States, state)
		return nil
	}
}

func WithNotConnState(state conntrack.State) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.NotConnStateMatcher](r)
		if !ok {
			m = &matcher.NotConnStateMatcher{}
			r.Matchers = append(r.Matchers, m)
		}
		m.States = append(m.States, state)
		return nil
	}
}

func WithName(name string) RuleOption {
	return func(r *Rule) error {
		r.Name = name
		return nil
	}
}

func WithPayload(pattern string) RuleOption {
	return func(r *Rule) error {
		pm, err := payload.New(pattern)
		if err != nil {
			return fmt.Errorf("invalid payload regex %q: %w", pattern, err)
		}
		m, ok := findMatcher[*matcher.PayloadMatcher](r)
		if !ok {
			m = &matcher.PayloadMatcher{}
			r.Matchers = append(r.Matchers, m)
		}
		m.Payload = pm
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

func WithProto(p proto.Proto) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.ProtoMatcher](r)
		if !ok {
			m = &matcher.ProtoMatcher{Protos: set.NewProtoSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Protos.Add(p); err != nil {
			return fmt.Errorf("invalid protocol %v", p)
		}
		return nil
	}
}

func WithNotProto(p proto.Proto) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.NotProtoMatcher](r)
		if !ok {
			m = &matcher.NotProtoMatcher{Protos: set.NewProtoSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Protos.Add(p); err != nil {
			return fmt.Errorf("invalid protocol %v", p)
		}
		return nil
	}
}

// Source port options.

func WithSrcPort(port uint16) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.SrcPortMatcher](r)
		if !ok {
			m = &matcher.SrcPortMatcher{Ports: set.NewPortSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ports.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithNotSrcPort(port uint16) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.NotSrcPortMatcher](r)
		if !ok {
			m = &matcher.NotSrcPortMatcher{Ports: set.NewPortSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ports.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.SrcSetMatcher{Set: s})
		return nil
	}
}

func WithNotSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotSrcSetMatcher{Set: s})
		return nil
	}
}

func WithSrcIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.SrcSetMatcher{Set: s})
		return nil
	}
}

func WithNotSrcIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotSrcSetMatcher{Set: s})
		return nil
	}
}

// Destination port options.

func WithDstPort(port uint16) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.DstPortMatcher](r)
		if !ok {
			m = &matcher.DstPortMatcher{Ports: set.NewPortSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ports.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithNotDstPort(port uint16) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.NotDstPortMatcher](r)
		if !ok {
			m = &matcher.NotDstPortMatcher{Ports: set.NewPortSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ports.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.DstSetMatcher{Set: s})
		return nil
	}
}

func WithNotDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotDstSetMatcher{Set: s})
		return nil
	}
}

func WithDstIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.DstSetMatcher{Set: s})
		return nil
	}
}

func WithNotDstIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotDstSetMatcher{Set: s})
		return nil
	}
}

// Source address options.

func WithSrcNet(cidr string) RuleOption {
	return func(r *Rule) error {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		m, ok := findMatcher[*matcher.SrcNetMatcher](r)
		if !ok {
			m = &matcher.SrcNetMatcher{Nets: set.NewIPSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Nets.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithNotSrcNet(cidr string) RuleOption {
	return func(r *Rule) error {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		m, ok := findMatcher[*matcher.NotSrcNetMatcher](r)
		if !ok {
			m = &matcher.NotSrcNetMatcher{Nets: set.NewIPSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Nets.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.SrcSetMatcher{Set: s})
		return nil
	}
}

func WithNotSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotSrcSetMatcher{Set: s})
		return nil
	}
}

// Destination address options.

func WithDstNet(cidr string) RuleOption {
	return func(r *Rule) error {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		m, ok := findMatcher[*matcher.DstNetMatcher](r)
		if !ok {
			m = &matcher.DstNetMatcher{Nets: set.NewIPSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Nets.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithNotDstNet(cidr string) RuleOption {
	return func(r *Rule) error {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		m, ok := findMatcher[*matcher.NotDstNetMatcher](r)
		if !ok {
			m = &matcher.NotDstNetMatcher{Nets: set.NewIPSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Nets.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.DstSetMatcher{Set: s})
		return nil
	}
}

func WithNotDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotDstSetMatcher{Set: s})
		return nil
	}
}

// Source interface options.

func WithSrcIface(iface string) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.SrcIfaceMatcher](r)
		if !ok {
			m = &matcher.SrcIfaceMatcher{Ifaces: set.NewIfaceSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ifaces.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithNotSrcIface(iface string) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.NotSrcIfaceMatcher](r)
		if !ok {
			m = &matcher.NotSrcIfaceMatcher{Ifaces: set.NewIfaceSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ifaces.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

// Destination interface options.

func WithDstIface(iface string) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.DstIfaceMatcher](r)
		if !ok {
			m = &matcher.DstIfaceMatcher{Ifaces: set.NewIfaceSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ifaces.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithNotDstIface(iface string) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.NotDstIfaceMatcher](r)
		if !ok {
			m = &matcher.NotDstIfaceMatcher{Ifaces: set.NewIfaceSet()}
			r.Matchers = append(r.Matchers, m)
		}
		if err := m.Ifaces.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithSrcIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.SrcSetMatcher{Set: s})
		return nil
	}
}

func WithNotSrcIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotSrcSetMatcher{Set: s})
		return nil
	}
}

func WithDstIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.DstSetMatcher{Set: s})
		return nil
	}
}

func WithNotDstIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Matchers = append(r.Matchers, &matcher.NotDstSetMatcher{Set: s})
		return nil
	}
}

func NewRule(opts ...RuleOption) (*Rule, error) {
	r := Rule{
		packetCount: counter.New(),
	}
	for _, o := range opts {
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

	Matchers []matcher.Matcher

	packetCount *counter.Counter
}

func (r *Rule) Match(pkt *packet.Packet) bool {
	return r.MatchWithConntrackState(pkt, conntrack.StateNew)
}

func (r *Rule) MatchWithConntrackState(pkt *packet.Packet, state conntrack.State) bool {
	if state == "" {
		state = conntrack.StateNew
	}
	for _, m := range r.Matchers {
		ok, err := m.Match(pkt, state)
		if err != nil || !ok {
			return false
		}
	}
	// All conditions passed - increment packet counter
	r.packetCount.Increment()
	return true
}

func (r *Rule) PacketCount() uint64 {
	return r.packetCount.Get()
}

func (r *Rule) IncrementPacketCount() {
	r.packetCount.Increment()
}

func (r *Rule) ResetPacketCount() {
	r.packetCount.Reset()
}
