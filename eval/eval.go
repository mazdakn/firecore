package eval

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/rule"
)

// Result is the outcome of evaluating a packet with Engine.Evaluate.
type Result struct {
	// Verdict is the final decision, or nil if no table decided.
	Verdict *rule.Action
	// Trace lists every rule inspected during evaluation, in the order
	// evaluated, regardless of whether each one matched.
	Trace []*rule.Rule
	// ConnState is the connection state the packet was classified as by
	// the engine's conntrack tracker, or nil if conntrack is disabled.
	ConnState *conntrack.State
}
