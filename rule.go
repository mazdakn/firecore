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

type RuleOption func(*Rule) error

// unwrapForPolarity reports whether m's negation matches negate: a plain
// matcher matches negate == false, and a matcher.Negated wrapper matches
// negate == true (in which case its inner matcher is returned). It is the
// shared building block for finding an existing matcher to extend, since
// merging (e.g. repeated WithSrcPort calls) must never cross polarity —
// WithSrcPort and WithNotSrcPort must never share one underlying set.
func unwrapForPolarity(m matcher.Matcher, negate bool) (matcher.Matcher, bool) {
	neg, isNegated := m.(matcher.Negated)
	if isNegated != negate {
		return nil, false
	}
	if isNegated {
		return neg.Matcher, true
	}
	return m, true
}

// findMatcher returns the first matcher in r.Matchers of concrete type M
// whose negation matches negate, so RuleOptions that extend an existing
// condition (e.g. repeated WithConnState calls) can reuse it instead of
// adding a redundant Matcher.
func findMatcher[M matcher.Matcher](r *Rule, negate bool) (M, bool) {
	for _, m := range r.Matchers {
		candidate, ok := unwrapForPolarity(m, negate)
		if !ok {
			continue
		}
		if match, ok := candidate.(M); ok {
			return match, true
		}
	}
	var zero M
	return zero, false
}

// findSrcSet returns the set.Set of an existing SrcSetMatcher on r matching
// negate and kind. SrcSetMatcher is shared by port/net/iface conditions, so
// unlike findMatcher this must also filter on the wrapped set's kind —
// otherwise, say, WithSrcPort could accumulate into a set built by WithSrcNet.
func findSrcSet(r *Rule, negate bool, kind set.Type) (set.Set, bool) {
	for _, m := range r.Matchers {
		candidate, ok := unwrapForPolarity(m, negate)
		if !ok {
			continue
		}
		sm, ok := candidate.(*matcher.SrcSetMatcher)
		if !ok || sm.Set.Type() != kind {
			continue
		}
		return sm.Set, true
	}
	return nil, false
}

// findDstSet is findSrcSet's DstSetMatcher counterpart.
func findDstSet(r *Rule, negate bool, kind set.Type) (set.Set, bool) {
	for _, m := range r.Matchers {
		candidate, ok := unwrapForPolarity(m, negate)
		if !ok {
			continue
		}
		dm, ok := candidate.(*matcher.DstSetMatcher)
		if !ok || dm.Set.Type() != kind {
			continue
		}
		return dm.Set, true
	}
	return nil, false
}

// addMatcher appends m to r.Matchers, wrapping it in matcher.Negate first if
// negate is true. It is the single place a matcher gets attached to a rule.
func addMatcher(r *Rule, m matcher.Matcher, negate bool) {
	if negate {
		m = matcher.Negate(m)
	}
	r.Matchers = append(r.Matchers, m)
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

		m, ok := findMatcher[*matcher.ConnStateMatcher](r, negate)
		if !ok {
			m = &matcher.ConnStateMatcher{}
			addMatcher(r, m, negate)
		}
		m.States = append(m.States, parsed)
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
		pm, err := payload.New(pattern)
		if err != nil {
			return fmt.Errorf("invalid payload regex %q: %w", pattern, err)
		}
		m, ok := findMatcher[*matcher.PayloadMatcher](r, false)
		if !ok {
			m = &matcher.PayloadMatcher{}
			addMatcher(r, m, false)
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

func withProto(p proto.Proto, negate bool) RuleOption {
	return func(r *Rule) error {
		m, ok := findMatcher[*matcher.ProtoMatcher](r, negate)
		if !ok {
			m = &matcher.ProtoMatcher{Protos: set.NewProtoSet()}
			addMatcher(r, m, negate)
		}
		if err := m.Protos.Add(p); err != nil {
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

// Source port options.

func withSrcPort(port uint16, negate bool) RuleOption {
	return func(r *Rule) error {
		s, ok := findSrcSet(r, negate, set.TypePort)
		var ports *set.PortSet
		if ok {
			ports = s.(*set.PortSet)
		} else {
			ports = set.NewPortSet()
			addMatcher(r, &matcher.SrcSetMatcher{Set: ports}, negate)
		}
		if err := ports.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithSrcPort(port uint16) RuleOption {
	return withSrcPort(port, false)
}

func WithNotSrcPort(port uint16) RuleOption {
	return withSrcPort(port, true)
}

// validateSet reports an error if s is nil.
func validateSet(s set.Set) error {
	if s == nil {
		return fmt.Errorf("set must not be nil")
	}
	return nil
}

// WithSrcSet matches packets whose source-derived value (address, port, or
// interface, depending on s's Type) is in s.
func WithSrcSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		if err := validateSet(s); err != nil {
			return err
		}
		addMatcher(r, &matcher.SrcSetMatcher{Set: s}, false)
		return nil
	}
}

// WithNotSrcSet matches packets whose source-derived value is not in s.
func WithNotSrcSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		if err := validateSet(s); err != nil {
			return err
		}
		addMatcher(r, &matcher.SrcSetMatcher{Set: s}, true)
		return nil
	}
}

// Destination port options.

func withDstPort(port uint16, negate bool) RuleOption {
	return func(r *Rule) error {
		s, ok := findDstSet(r, negate, set.TypePort)
		var ports *set.PortSet
		if ok {
			ports = s.(*set.PortSet)
		} else {
			ports = set.NewPortSet()
			addMatcher(r, &matcher.DstSetMatcher{Set: ports}, negate)
		}
		if err := ports.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithDstPort(port uint16) RuleOption {
	return withDstPort(port, false)
}

func WithNotDstPort(port uint16) RuleOption {
	return withDstPort(port, true)
}

// WithDstSet matches packets whose destination-derived value (address, port,
// or interface, depending on s's Type) is in s.
func WithDstSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		if err := validateSet(s); err != nil {
			return err
		}
		addMatcher(r, &matcher.DstSetMatcher{Set: s}, false)
		return nil
	}
}

// WithNotDstSet matches packets whose destination-derived value is not in s.
func WithNotDstSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		if err := validateSet(s); err != nil {
			return err
		}
		addMatcher(r, &matcher.DstSetMatcher{Set: s}, true)
		return nil
	}
}

// Source address options.

// parseCIDR parses cidr, returning a consistently-formatted error on failure.
func parseCIDR(cidr string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("CIDR %s is invalid", cidr)
	}
	return ipnet, nil
}

func withSrcNet(cidr string, negate bool) RuleOption {
	return func(r *Rule) error {
		ipnet, err := parseCIDR(cidr)
		if err != nil {
			return err
		}
		s, ok := findSrcSet(r, negate, set.TypeIP)
		var nets *set.IPSet
		if ok {
			nets = s.(*set.IPSet)
		} else {
			nets = set.NewIPSet()
			addMatcher(r, &matcher.SrcSetMatcher{Set: nets}, negate)
		}
		if err := nets.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithSrcNet(cidr string) RuleOption {
	return withSrcNet(cidr, false)
}

func WithNotSrcNet(cidr string) RuleOption {
	return withSrcNet(cidr, true)
}

// Destination address options.

func withDstNet(cidr string, negate bool) RuleOption {
	return func(r *Rule) error {
		ipnet, err := parseCIDR(cidr)
		if err != nil {
			return err
		}
		s, ok := findDstSet(r, negate, set.TypeIP)
		var nets *set.IPSet
		if ok {
			nets = s.(*set.IPSet)
		} else {
			nets = set.NewIPSet()
			addMatcher(r, &matcher.DstSetMatcher{Set: nets}, negate)
		}
		if err := nets.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithDstNet(cidr string) RuleOption {
	return withDstNet(cidr, false)
}

func WithNotDstNet(cidr string) RuleOption {
	return withDstNet(cidr, true)
}

// Source interface options.

func withSrcIface(iface string, negate bool) RuleOption {
	return func(r *Rule) error {
		s, ok := findSrcSet(r, negate, set.TypeIface)
		var ifaces *set.IfaceSet
		if ok {
			ifaces = s.(*set.IfaceSet)
		} else {
			ifaces = set.NewIfaceSet()
			addMatcher(r, &matcher.SrcSetMatcher{Set: ifaces}, negate)
		}
		if err := ifaces.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithSrcIface(iface string) RuleOption {
	return withSrcIface(iface, false)
}

func WithNotSrcIface(iface string) RuleOption {
	return withSrcIface(iface, true)
}

// Destination interface options.

func withDstIface(iface string, negate bool) RuleOption {
	return func(r *Rule) error {
		s, ok := findDstSet(r, negate, set.TypeIface)
		var ifaces *set.IfaceSet
		if ok {
			ifaces = s.(*set.IfaceSet)
		} else {
			ifaces = set.NewIfaceSet()
			addMatcher(r, &matcher.DstSetMatcher{Set: ifaces}, negate)
		}
		if err := ifaces.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithDstIface(iface string) RuleOption {
	return withDstIface(iface, false)
}

func WithNotDstIface(iface string) RuleOption {
	return withDstIface(iface, true)
}

func NewRule(opts ...RuleOption) (*Rule, error) {
	r := Rule{
		packetCount: counter.New(),
		byteCount:   counter.New(),
	}
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

	Matchers []matcher.Matcher

	packetCount *counter.Counter
	byteCount   *counter.Counter
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
	for _, m := range r.Matchers {
		if !m.Match(pkt, state) {
			return false
		}
	}
	// All conditions passed - increment packet and byte counters
	r.packetCount.Increment()
	r.byteCount.Add(uint64(pkt.Size))
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

func (r *Rule) ByteCount() uint64 {
	return r.byteCount.Get()
}

func (r *Rule) AddByteCount(n uint64) {
	r.byteCount.Add(n)
}

func (r *Rule) ResetByteCount() {
	r.byteCount.Reset()
}
