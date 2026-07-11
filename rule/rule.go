package rule

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/counter"
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
		r.ConnState = append(r.ConnState, state)
		return nil
	}
}

func WithNotConnState(state conntrack.State) RuleOption {
	return func(r *Rule) error {
		r.NotConnState = append(r.NotConnState, state)
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
		matcher, err := payload.New(pattern)
		if err != nil {
			return fmt.Errorf("invalid payload regex %q: %w", pattern, err)
		}
		r.Payload = matcher
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
		if r.Proto == nil {
			r.Proto = set.NewProtoSet()
		}
		if err := r.Proto.Add(p); err != nil {
			return fmt.Errorf("invalid protocol %v", p)
		}
		return nil
	}
}

func WithNotProto(p proto.Proto) RuleOption {
	return func(r *Rule) error {
		if r.NotProto == nil {
			r.NotProto = set.NewProtoSet()
		}
		if err := r.NotProto.Add(p); err != nil {
			return fmt.Errorf("invalid protocol %v", p)
		}
		return nil
	}
}

// Source port options.

func WithSrcPort(port uint16) RuleOption {
	return func(r *Rule) error {
		if r.Source.Port == nil {
			r.Source.Port = set.NewPortSet()
		}
		if err := r.Source.Port.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithNotSrcPort(port uint16) RuleOption {
	return func(r *Rule) error {
		if r.NotSource.Port == nil {
			r.NotSource.Port = set.NewPortSet()
		}
		if err := r.NotSource.Port.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Source.Sets = append(r.Source.Sets, s)
		return nil
	}
}

func WithNotSrcPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
		return nil
	}
}

func WithSrcIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Source.Sets = append(r.Source.Sets, s)
		return nil
	}
}

func WithNotSrcIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
		return nil
	}
}

// Destination port options.

func WithDstPort(port uint16) RuleOption {
	return func(r *Rule) error {
		if r.Destination.Port == nil {
			r.Destination.Port = set.NewPortSet()
		}
		if err := r.Destination.Port.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithNotDstPort(port uint16) RuleOption {
	return func(r *Rule) error {
		if r.NotDestination.Port == nil {
			r.NotDestination.Port = set.NewPortSet()
		}
		if err := r.NotDestination.Port.Add(port); err != nil {
			return fmt.Errorf("invalid port %d", port)
		}
		return nil
	}
}

func WithDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Destination.Sets = append(r.Destination.Sets, s)
		return nil
	}
}

func WithNotDstPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
		return nil
	}
}

func WithDstIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Destination.Sets = append(r.Destination.Sets, s)
		return nil
	}
}

func WithNotDstIPPortSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
		return nil
	}
}

// Source address options.

func WithSrcNet(cidr string) RuleOption {
	return func(r *Rule) error {
		if r.Source.Net == nil {
			r.Source.Net = set.NewIPSet()
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		if err := r.Source.Net.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithNotSrcNet(cidr string) RuleOption {
	return func(r *Rule) error {
		if r.NotSource.Net == nil {
			r.NotSource.Net = set.NewIPSet()
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		if err := r.NotSource.Net.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Source.Sets = append(r.Source.Sets, s)
		return nil
	}
}

func WithNotSrcIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
		return nil
	}
}

// Source address options.

func WithDstNet(cidr string) RuleOption {
	return func(r *Rule) error {
		if r.Destination.Net == nil {
			r.Destination.Net = set.NewIPSet()
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		if err := r.Destination.Net.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithNotDstNet(cidr string) RuleOption {
	return func(r *Rule) error {
		if r.NotDestination.Net == nil {
			r.NotDestination.Net = set.NewIPSet()
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR %s is invalid", cidr)
		}
		if err := r.NotDestination.Net.Add(ipnet); err != nil {
			return fmt.Errorf("error adding %s to set: %w", cidr, err)
		}
		return nil
	}
}

func WithDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Destination.Sets = append(r.Destination.Sets, s)
		return nil
	}
}

func WithNotDstIPSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
		return nil
	}
}

// Source interface options.

func WithSrcIface(iface string) RuleOption {
	return func(r *Rule) error {
		if r.Source.Iface == nil {
			r.Source.Iface = set.NewIfaceSet()
		}
		if err := r.Source.Iface.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithNotSrcIface(iface string) RuleOption {
	return func(r *Rule) error {
		if r.NotSource.Iface == nil {
			r.NotSource.Iface = set.NewIfaceSet()
		}
		if err := r.NotSource.Iface.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

// Destination interface options.

func WithDstIface(iface string) RuleOption {
	return func(r *Rule) error {
		if r.Destination.Iface == nil {
			r.Destination.Iface = set.NewIfaceSet()
		}
		if err := r.Destination.Iface.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithNotDstIface(iface string) RuleOption {
	return func(r *Rule) error {
		if r.NotDestination.Iface == nil {
			r.NotDestination.Iface = set.NewIfaceSet()
		}
		if err := r.NotDestination.Iface.Add(iface); err != nil {
			return fmt.Errorf("invalid interface %s", iface)
		}
		return nil
	}
}

func WithSrcIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Source.Sets = append(r.Source.Sets, s)
		return nil
	}
}

func WithNotSrcIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotSource.Sets = append(r.NotSource.Sets, s)
		return nil
	}
}

func WithDstIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.Destination.Sets = append(r.Destination.Sets, s)
		return nil
	}
}

func WithNotDstIfaceSet(s set.Set) RuleOption {
	return func(r *Rule) error {
		r.NotDestination.Sets = append(r.NotDestination.Sets, s)
		return nil
	}
}

func New(opts ...RuleOption) (*Rule, error) {
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

// Endpoint groups the network, port, and interface match criteria for one traffic direction.
type Endpoint struct {
	Net   *set.IPSet
	Port  *set.PortSet
	Iface *set.IfaceSet
	Sets  []set.Set
}

type Rule struct {
	Name        string
	Order       uint64
	Source      Endpoint
	Destination Endpoint
	Proto       *set.ProtoSet

	NotSource      Endpoint
	NotDestination Endpoint
	NotProto       *set.ProtoSet
	ConnState      []conntrack.State
	NotConnState   []conntrack.State
	Payload        *payload.Matcher

	Action     Action
	JumpTarget string // name of the chain to jump to when Action == Jump

	packetCount *counter.Counter
}

func (r *Rule) Match(pkt *packet.Packet) bool {
	return r.MatchWithConntrackState(pkt, conntrack.StateNew)
}

func (r *Rule) MatchWithConntrackState(pkt *packet.Packet, state conntrack.State) bool {
	if state == "" {
		state = conntrack.StateNew
	}
	if len(r.ConnState) > 0 && !slices.Contains(r.ConnState, state) {
		return false
	}
	if len(r.NotConnState) > 0 && slices.Contains(r.NotConnState, state) {
		return false
	}
	if r.Payload != nil && !r.Payload.Match(pkt.Payload) {
		return false
	}
	if r.Proto != nil && !r.Proto.Match(pkt.Proto) {
		return false
	}
	if r.NotProto != nil && r.NotProto.Match(pkt.Proto) {
		return false
	}
	if r.Source.Port != nil && !r.Source.Port.Match(pkt.SrcPort) {
		return false
	}
	if r.NotSource.Port != nil && r.NotSource.Port.Match(pkt.SrcPort) {
		return false
	}
	if r.Destination.Port != nil && !r.Destination.Port.Match(pkt.DstPort) {
		return false
	}
	if r.NotDestination.Port != nil && r.NotDestination.Port.Match(pkt.DstPort) {
		return false
	}
	if r.Source.Net != nil && !r.Source.Net.Match(pkt.SrcAddr) {
		return false
	}
	if r.NotSource.Net != nil && r.NotSource.Net.Match(pkt.SrcAddr) {
		return false
	}
	if r.Destination.Net != nil && !r.Destination.Net.Match(pkt.DstAddr) {
		return false
	}
	if r.NotDestination.Net != nil && r.NotDestination.Net.Match(pkt.DstAddr) {
		return false
	}
	srcIPPort := set.IPPortTuple{IP: pkt.SrcAddr, Port: pkt.SrcPort}
	dstIPPort := set.IPPortTuple{IP: pkt.DstAddr, Port: pkt.DstPort}
	if !matchAllNamedSets(r.Source.Sets, pkt.SrcAddr, pkt.SrcPort, srcIPPort, pkt.Metadata.IngressIface) {
		return false
	}
	if !matchAllNamedSets(r.Destination.Sets, pkt.DstAddr, pkt.DstPort, dstIPPort, pkt.Metadata.EgressIface) {
		return false
	}
	if matchAnyNamedSet(r.NotSource.Sets, pkt.SrcAddr, pkt.SrcPort, srcIPPort, pkt.Metadata.IngressIface) {
		return false
	}
	if matchAnyNamedSet(r.NotDestination.Sets, pkt.DstAddr, pkt.DstPort, dstIPPort, pkt.Metadata.EgressIface) {
		return false
	}
	if r.Source.Iface != nil && !r.Source.Iface.Match(pkt.Metadata.IngressIface) {
		return false
	}
	if r.NotSource.Iface != nil && r.NotSource.Iface.Match(pkt.Metadata.IngressIface) {
		return false
	}
	if r.Destination.Iface != nil && !r.Destination.Iface.Match(pkt.Metadata.EgressIface) {
		return false
	}
	if r.NotDestination.Iface != nil && r.NotDestination.Iface.Match(pkt.Metadata.EgressIface) {
		return false
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

// String returns the rule's name when one is set, otherwise a compact
// description of its match conditions and action (see Description).
func (r *Rule) String() string {
	if r.Name != "" {
		return r.Name
	}
	return r.Description()
}

// Description always returns a compact representation of the rule's action
// and match conditions, regardless of whether a name is set.
func (r *Rule) Description() string {
	return fmt.Sprintf("%s %s", r.Action, r.MatchConditions())
}

// MatchConditions returns a compact string describing only the match criteria
// (protocol, source, destination, interfaces) without the action.
func (r *Rule) MatchConditions() string {
	proto := "*"
	switch {
	case r.Proto != nil && r.NotProto != nil:
		proto = r.Proto.String() + ",!" + r.NotProto.String()
	case r.Proto != nil:
		proto = r.Proto.String()
	case r.NotProto != nil:
		proto = "!" + r.NotProto.String()
	}
	srcPort := "*"
	switch {
	case r.Source.Port != nil && r.NotSource.Port != nil:
		srcPort = r.Source.Port.String() + ",!" + r.NotSource.Port.String()
	case r.Source.Port != nil:
		srcPort = r.Source.Port.String()
	case r.NotSource.Port != nil:
		srcPort = "!" + r.NotSource.Port.String()
	}
	srcPort = appendSetStrings(srcPort, filterEndpointSetsByType(r.Source.Sets, set.TypePort))
	srcPort = appendSetStrings(srcPort, filterEndpointSetsByType(r.Source.Sets, set.TypeIPPort))
	srcPort = appendNotSetStrings(srcPort, filterEndpointSetsByType(r.NotSource.Sets, set.TypePort))
	srcPort = appendNotSetStrings(srcPort, filterEndpointSetsByType(r.NotSource.Sets, set.TypeIPPort))

	dstPort := "*"
	switch {
	case r.Destination.Port != nil && r.NotDestination.Port != nil:
		dstPort = r.Destination.Port.String() + ",!" + r.NotDestination.Port.String()
	case r.Destination.Port != nil:
		dstPort = r.Destination.Port.String()
	case r.NotDestination.Port != nil:
		dstPort = "!" + r.NotDestination.Port.String()
	}
	dstPort = appendSetStrings(dstPort, filterEndpointSetsByType(r.Destination.Sets, set.TypePort))
	dstPort = appendSetStrings(dstPort, filterEndpointSetsByType(r.Destination.Sets, set.TypeIPPort))
	dstPort = appendNotSetStrings(dstPort, filterEndpointSetsByType(r.NotDestination.Sets, set.TypePort))
	dstPort = appendNotSetStrings(dstPort, filterEndpointSetsByType(r.NotDestination.Sets, set.TypeIPPort))

	srcNet := "*"
	switch {
	case r.Source.Net != nil && r.NotSource.Net != nil:
		srcNet = r.Source.Net.String() + ",!" + r.NotSource.Net.String()
	case r.Source.Net != nil:
		srcNet = r.Source.Net.String()
	case r.NotSource.Net != nil:
		srcNet = "!" + r.NotSource.Net.String()
	}
	srcNet = appendSetStrings(srcNet, filterEndpointSetsByType(r.Source.Sets, set.TypeIP))
	srcNet = appendNotSetStrings(srcNet, filterEndpointSetsByType(r.NotSource.Sets, set.TypeIP))

	dstNet := "*"
	switch {
	case r.Destination.Net != nil && r.NotDestination.Net != nil:
		dstNet = r.Destination.Net.String() + ",!" + r.NotDestination.Net.String()
	case r.Destination.Net != nil:
		dstNet = r.Destination.Net.String()
	case r.NotDestination.Net != nil:
		dstNet = "!" + r.NotDestination.Net.String()
	}
	dstNet = appendSetStrings(dstNet, filterEndpointSetsByType(r.Destination.Sets, set.TypeIP))
	dstNet = appendNotSetStrings(dstNet, filterEndpointSetsByType(r.NotDestination.Sets, set.TypeIP))

	base := fmt.Sprintf("%s{%s:%s->%s:%s}", proto, srcNet, srcPort, dstNet, dstPort)

	ingressIfaceSets := filterEndpointSetsByType(r.Source.Sets, set.TypeIface)
	notIngressIfaceSets := filterEndpointSetsByType(r.NotSource.Sets, set.TypeIface)
	egressIfaceSets := filterEndpointSetsByType(r.Destination.Sets, set.TypeIface)
	notEgressIfaceSets := filterEndpointSetsByType(r.NotDestination.Sets, set.TypeIface)

	if r.Source.Iface != nil || r.NotSource.Iface != nil || len(ingressIfaceSets) > 0 || len(notIngressIfaceSets) > 0 {
		iface := ""
		if r.Source.Iface != nil {
			iface = r.Source.Iface.String()
		}
		if r.NotSource.Iface != nil {
			neg := "!" + r.NotSource.Iface.String()
			if iface == "" {
				iface = neg
			} else {
				iface += "," + neg
			}
		}
		iface = appendSetStrings(iface, ingressIfaceSets)
		iface = appendNotSetStrings(iface, notIngressIfaceSets)
		base += " ingress_iface=" + iface
	}
	if r.Destination.Iface != nil || r.NotDestination.Iface != nil || len(egressIfaceSets) > 0 || len(notEgressIfaceSets) > 0 {
		iface := ""
		if r.Destination.Iface != nil {
			iface = r.Destination.Iface.String()
		}
		if r.NotDestination.Iface != nil {
			neg := "!" + r.NotDestination.Iface.String()
			if iface == "" {
				iface = neg
			} else {
				iface += "," + neg
			}
		}
		iface = appendSetStrings(iface, egressIfaceSets)
		iface = appendNotSetStrings(iface, notEgressIfaceSets)
		base += " egress_iface=" + iface
	}
	if len(r.ConnState) > 0 || len(r.NotConnState) > 0 {
		connStates := formatConnStates(r.ConnState, r.NotConnState)
		base += " ct_state=" + connStates
	}
	if r.Payload != nil {
		base += fmt.Sprintf(" payload~=%q", r.Payload.String())
	}
	return base
}

func formatConnStates(states []conntrack.State, notStates []conntrack.State) string {
	parts := make([]string, 0, len(states)+len(notStates))
	for _, state := range states {
		parts = append(parts, state.String())
	}
	for _, state := range notStates {
		parts = append(parts, "!"+state.String())
	}
	return strings.Join(parts, ",")
}

// matchAllNamedSets returns true when every set in sets matches the packet
// value corresponding to the set's type.
func matchAllNamedSets(sets []set.Set, ip any, port any, ipPort any, iface any) bool {
	for _, s := range sets {
		if !matchNamedSetByType(s, ip, port, ipPort, iface) {
			return false
		}
	}
	return true
}

// matchAnyNamedSet returns true when any set in sets matches the packet value
// corresponding to the set's type.
func matchAnyNamedSet(sets []set.Set, ip any, port any, ipPort any, iface any) bool {
	for _, s := range sets {
		if matchNamedSetByType(s, ip, port, ipPort, iface) {
			return true
		}
	}
	return false
}

func matchNamedSetByType(s set.Set, ip any, port any, ipPort any, iface any) bool {
	switch s.Type() {
	case set.TypeIP:
		return s.Match(ip)
	case set.TypePort:
		return s.Match(port)
	case set.TypeIPPort:
		return s.Match(ipPort)
	case set.TypeIface:
		return s.Match(iface)
	default:
		return false
	}
}

// appendSetString appends the string representation of s to base, separated
// by a comma.  If base is "*" (wildcard), s replaces it entirely.
// If s does not implement fmt.Stringer, base is returned unchanged.
func appendSetString(base string, s set.Set) string {
	if s == nil {
		return base
	}
	st, ok := s.(fmt.Stringer)
	if !ok {
		return base
	}
	if base == "*" || base == "" {
		return st.String()
	}
	return base + "," + st.String()
}

// appendNotSetString is like appendSetString but prefixes the set string with
// "!" to indicate a negated match constraint.
func appendNotSetString(base string, s set.Set) string {
	if s == nil {
		return base
	}
	st, ok := s.(fmt.Stringer)
	if !ok {
		return base
	}
	neg := "!" + st.String()
	if base == "*" || base == "" {
		return neg
	}
	return base + "," + neg
}

func appendSetStrings(base string, sets []set.Set) string {
	for _, s := range sets {
		base = appendSetString(base, s)
	}
	return base
}

func appendNotSetStrings(base string, sets []set.Set) string {
	for _, s := range sets {
		base = appendNotSetString(base, s)
	}
	return base
}

func filterEndpointSetsByType(sets []set.Set, t set.Type) []set.Set {
	filtered := make([]set.Set, 0, len(sets))
	for _, s := range sets {
		if s.Type() == t {
			filtered = append(filtered, s)
		}
	}
	return filtered
}
