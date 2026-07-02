package match

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/rule"
)

type MatchContext struct {
	Packet    *packet.Packet
	ConnState conntrack.State
	Verdict   *rule.Action
	Trace     []*rule.Rule

	// ExpectedVerdict is the verdict expected by the intent. When nil, verdict
	// validation is skipped.
	ExpectedVerdict *rule.Action
	// HitByRule is the name of the rule expected to match the packet. When non-empty,
	// it is checked against the last rule recorded in Trace after matching.
	HitByRule string
}

type MatchContextOption func(*MatchContext)

// WithExpectedVerdict sets the verdict the intent expects the packet to receive.
func WithExpectedVerdict(a rule.Action) MatchContextOption {
	return func(mc *MatchContext) {
		mc.ExpectedVerdict = &a
	}
}

// WithExpectedRule sets the name of the rule expected to be the decisive match.
func WithExpectedRule(name string) MatchContextOption {
	return func(mc *MatchContext) {
		mc.HitByRule = name
	}
}

func New(pkt *packet.Packet, opts ...MatchContextOption) *MatchContext {
	mc := &MatchContext{
		Packet:    pkt,
		ConnState: conntrack.StateNew,
	}
	for _, opt := range opts {
		opt(mc)
	}
	return mc
}

// VerdictMatches reports whether the actual verdict satisfies the intent.
// Returns true when no expected verdict was specified (nil).
func (mc *MatchContext) VerdictMatches() bool {
	if mc.ExpectedVerdict == nil {
		return true
	}
	if mc.Verdict == nil {
		return false
	}
	return *mc.ExpectedVerdict == *mc.Verdict
}

// RuleMatches reports whether the expected rule was the decisive rule that
// determined the verdict. Returns true when no expected rule was specified.
// Returns false when the verdict is nil (no rule fired).
func (mc *MatchContext) RuleMatches() bool {
	if mc.HitByRule == "" {
		return true
	}
	if mc.Verdict == nil || len(mc.Trace) == 0 {
		return false
	}
	return mc.Trace[len(mc.Trace)-1].Name == mc.HitByRule
}
