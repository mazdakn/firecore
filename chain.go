package firecore

import (
	"fmt"
	"sort"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
)

// MaxJumpDepth caps how many nested Jump rules a single Match call will
// follow. It exists as a runtime safety net against jump cycles that were
// never checked with Table.Validate — without it, a cycle recurses until the
// goroutine stack overflows instead of returning an error.
const MaxJumpDepth = 64

// Chain holds an ordered slice of rules that are evaluated sequentially.
type Chain struct {
	Name  string
	Rules []*Rule
}

// NewChain creates a new, empty chain with the given name.
func NewChain(name string) (*Chain, error) {
	if name == "" {
		return nil, fmt.Errorf("chain name must not be empty")
	}
	return &Chain{Name: name}, nil
}

// AddRule inserts r into the chain, maintaining ascending order by Rule.Order.
// Unnamed rules (Rule.Name == "") are anonymous and may repeat; a non-empty
// name must be unique within the chain.
func (c *Chain) AddRule(r *Rule) error {
	if r == nil {
		return fmt.Errorf("rule must not be nil")
	}
	if r.Name != "" {
		for _, existing := range c.Rules {
			if existing.Name == r.Name {
				return fmt.Errorf("rule %q already exists in chain %q", r.Name, c.Name)
			}
		}
	}

	i := sort.Search(len(c.Rules), func(i int) bool {
		return c.Rules[i].Order > r.Order
	})
	c.Rules = append(c.Rules, nil)
	copy(c.Rules[i+1:], c.Rules[i:])
	c.Rules[i] = r
	return nil
}

// match evaluates the chain's rules against pkt.
//
// chains is the complete map of chains in the parent table, used to resolve
// Jump targets. depth counts the number of nested Jump calls taken to reach
// this chain (the entry chain is called with depth 0); it guards against jump
// cycles that Table.Validate wasn't run to catch. All evaluated rules
// (whether they match or not) are appended to result.Trace.
//
// Returns true if a rule set result.Verdict (Accept, Drop, or Pass) and
// evaluation is done; the caller distinguishes which via
// result.Verdict.IsTerminal(). Returns false if evaluation should resume in
// the calling context (Return action or no rule matched).
func (c *Chain) match(pkt *packet.Packet, result *Result, chains map[string]*Chain, depth int) (bool, error) {
	if depth > MaxJumpDepth {
		return false, fmt.Errorf("jump depth exceeded %d at chain %q: possible jump cycle", MaxJumpDepth, c.Name)
	}
	state := conntrack.StateNew
	if result.ConnState != nil {
		state = *result.ConnState
	}
	for _, r := range c.Rules {
		result.Trace = append(result.Trace, r)
		if r.MatchWithConntrackState(pkt, state) {
			switch r.Action {
			case Accept, Drop, Pass:
				result.Verdict = &r.Action
				return true, nil
			case Return:
				return false, nil
			case Jump:
				target, ok := chains[r.JumpTarget]
				if !ok {
					return false, fmt.Errorf("chain %q not found", r.JumpTarget)
				}
				terminated, err := target.match(pkt, result, chains, depth+1)
				if err != nil {
					return false, err
				}
				if terminated {
					return true, nil
				}
				// Target chain returned without a verdict; continue evaluating
				// the current chain at the next rule.
			}
		}
	}
	return false, nil
}
