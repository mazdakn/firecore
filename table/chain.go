package table

import (
	"fmt"
	"sort"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/eval"
	"github.com/mazdakn/firecore/rule"
)

// chainMatchResult indicates the outcome of evaluating a chain.
type chainMatchResult int

const (
	// chainContinue means no rule produced a terminal verdict; evaluation
	// should resume in the calling context (parent chain or table default).
	chainContinue chainMatchResult = iota
	// chainDecided means a terminal verdict (Accept or Drop) was recorded.
	chainDecided
	// chainPass means a Pass action was recorded; evaluation continues in
	// the next table.
	chainPass
)

// Chain holds an ordered slice of rules that are evaluated sequentially.
type Chain struct {
	Name  string
	Rules []*rule.Rule
}

// NewChain creates a new, empty chain with the given name.
func NewChain(name string) *Chain {
	return &Chain{Name: name}
}

// AddRule inserts r into the chain, maintaining ascending order by Rule.Order.
func (c *Chain) AddRule(r *rule.Rule) {
	i := sort.Search(len(c.Rules), func(i int) bool {
		return c.Rules[i].Order > r.Order
	})
	c.Rules = append(c.Rules, nil)
	copy(c.Rules[i+1:], c.Rules[i:])
	c.Rules[i] = r
}

// match evaluates the chain's rules against mc.
//
// chains is the complete map of chains in the parent table, used to resolve
// Jump targets. All evaluated rules (whether they match or not) are appended
// to result.Trace.
//
// Returns chainDecided if a terminal verdict (Accept/Drop) was set, chainPass
// if a Pass action was triggered, or chainContinue if evaluation should return
// to the calling context (Return action or no rule matched).
func (c *Chain) match(ctx *eval.Context, result *eval.Result, chains map[string]*Chain) chainMatchResult {
	var state conntrack.State
	if ctx.ConnState != nil {
		state = *ctx.ConnState
	}
	for _, r := range c.Rules {
		result.Trace = append(result.Trace, r)
		if r.MatchWithConntrackState(ctx.Packet, state) {
			switch r.Action {
			case rule.Accept, rule.Drop:
				result.Verdict = &r.Action
				return chainDecided
			case rule.Pass:
				result.Verdict = &r.Action
				return chainPass
			case rule.Return:
				return chainContinue
			case rule.Jump:
				target, ok := chains[r.JumpTarget]
				if !ok {
					panic(fmt.Sprintf("chain %q not found", r.JumpTarget))
				}
				matchResult := target.match(ctx, result, chains)
				if matchResult != chainContinue {
					return matchResult
				}
				// Target chain returned without a verdict; continue evaluating
				// the current chain at the next rule.
			}
		}
	}
	return chainContinue
}
