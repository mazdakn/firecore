package firecore

import (
	"fmt"
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

// findSet returns the set of an existing matcher M on r matching negate and
// predicate matchSet.
func findSet[M matcher.Matcher](r *Rule, negate bool, getSet func(M) set.Set, matchSet func(set.Set) bool) (set.Set, bool) {
	for _, m := range r.Matchers {
		candidate, ok := unwrapForPolarity(m, negate)
		if !ok {
			continue
		}
		sm, ok := candidate.(M)
		if !ok {
			continue
		}
		if s := getSet(sm); matchSet(s) {
			return s, true
		}
	}
	return nil, false
}

// findSrcSet returns the set.Set of an existing SrcSetMatcher on r matching
// negate and kind.
func findSrcSet(r *Rule, negate bool, kind set.Type) (set.Set, bool) {
	return findSet(r, negate,
		func(m *matcher.SrcSetMatcher) set.Set { return m.Set },
		func(s set.Set) bool { return s.Type() == kind },
	)
}

// findDstSet is findSrcSet's DstSetMatcher counterpart.
func findDstSet(r *Rule, negate bool, kind set.Type) (set.Set, bool) {
	return findSet(r, negate,
		func(m *matcher.DstSetMatcher) set.Set { return m.Set },
		func(s set.Set) bool { return s.Type() == kind },
	)
}

// addMatcher appends m to r.Matchers, wrapping it in matcher.Negate first if
// negate is true. It is the single place a matcher gets attached to a rule.
func addMatcher(r *Rule, m matcher.Matcher, negate bool) {
	if negate {
		m = matcher.Negate(m)
	}
	r.Matchers = append(r.Matchers, m)
}

// withSetEntry adds val to an existing set of type S on a matcher of type M
// with matching polarity, or creates a new S and attaches a new M if none
// exists yet.
func withSetEntry[S set.Set, M matcher.Matcher](
	newSet func() S,
	getSet func(M) set.Set,
	wrap func(set.Set) M,
	val any,
	negate bool,
) RuleOption {
	return func(r *Rule) error {
		if existing, ok := findSet(r, negate, getSet, func(s set.Set) bool {
			_, ok := s.(S)
			return ok
		}); ok {
			return existing.Add(val)
		}
		s := newSet()
		if err := s.Add(val); err != nil {
			return err
		}
		addMatcher(r, wrap(s), negate)
		return nil
	}
}

func withSrcEntry[S set.Set](newSet func() S, val any, negate bool) RuleOption {
	return withSetEntry(
		newSet,
		func(m *matcher.SrcSetMatcher) set.Set { return m.Set },
		func(s set.Set) *matcher.SrcSetMatcher { return &matcher.SrcSetMatcher{Set: s} },
		val,
		negate,
	)
}

func withDstEntry[S set.Set](newSet func() S, val any, negate bool) RuleOption {
	return withSetEntry(
		newSet,
		func(m *matcher.DstSetMatcher) set.Set { return m.Set },
		func(s set.Set) *matcher.DstSetMatcher { return &matcher.DstSetMatcher{Set: s} },
		val,
		negate,
	)
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

// Named set options.

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

// Source and destination port options.

func WithSrcPort(port uint16) RuleOption {
	return withSrcEntry(set.NewPortSet, port, false)
}

func WithNotSrcPort(port uint16) RuleOption {
	return withSrcEntry(set.NewPortSet, port, true)
}

func WithDstPort(port uint16) RuleOption {
	return withDstEntry(set.NewPortSet, port, false)
}

func WithNotDstPort(port uint16) RuleOption {
	return withDstEntry(set.NewPortSet, port, true)
}

// Source and destination address options.

func WithSrcNet(cidr string) RuleOption {
	return withSrcEntry(set.NewIPSet, cidr, false)
}

func WithNotSrcNet(cidr string) RuleOption {
	return withSrcEntry(set.NewIPSet, cidr, true)
}

func WithDstNet(cidr string) RuleOption {
	return withDstEntry(set.NewIPSet, cidr, false)
}

func WithNotDstNet(cidr string) RuleOption {
	return withDstEntry(set.NewIPSet, cidr, true)
}

// Source and destination address:port options.

func WithSrcAddrPort(addrPort string) RuleOption {
	return withSrcEntry(set.NewIPPortSet, addrPort, false)
}

func WithNotSrcAddrPort(addrPort string) RuleOption {
	return withSrcEntry(set.NewIPPortSet, addrPort, true)
}

func WithDstAddrPort(addrPort string) RuleOption {
	return withDstEntry(set.NewIPPortSet, addrPort, false)
}

func WithNotDstAddrPort(addrPort string) RuleOption {
	return withDstEntry(set.NewIPPortSet, addrPort, true)
}

// Source and destination interface options.

func WithSrcIface(iface string) RuleOption {
	return withSrcEntry(set.NewIfaceSet, iface, false)
}

func WithNotSrcIface(iface string) RuleOption {
	return withSrcEntry(set.NewIfaceSet, iface, true)
}

func WithDstIface(iface string) RuleOption {
	return withDstEntry(set.NewIfaceSet, iface, false)
}

func WithNotDstIface(iface string) RuleOption {
	return withDstEntry(set.NewIfaceSet, iface, true)
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
