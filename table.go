package firecore

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
)

// Table holds chains of firewall rules. Rules are accessed only via chains;
// a Table must have at least one chain.
type Table struct {
	Name        string
	Order       uint64
	Chains      map[string]*Chain
	entryChain  string
	DefaultRule *Rule
}

func NewTable(name string, order uint64, defaultAction Action) (*Table, error) {
	defaultRule, err := NewRule(
		WithAction(defaultAction),
		WithName(fmt.Sprintf("table %s default action", name)),
	)
	if err != nil {
		return nil, fmt.Errorf("create default rule: %w", err)
	}

	return &Table{
		Name:        name,
		Order:       order,
		Chains:      make(map[string]*Chain),
		DefaultRule: defaultRule,
	}, nil
}

// AddChain adds c to the table. The first chain added becomes the entry chain
// unless SetEntryChain is called explicitly.
func (t *Table) AddChain(c *Chain) {
	t.Chains[c.Name] = c
	if t.entryChain == "" {
		t.entryChain = c.Name
	}
}

// SetEntryChain designates the named chain as the entry point for packet
// evaluation.
func (t *Table) SetEntryChain(name string) {
	t.entryChain = name
}

// EntryChain returns the name of the entry chain for this table.
func (t *Table) EntryChain() string {
	return t.entryChain
}

// chainColor tracks DFS state for Validate's cycle check: white chains are
// unvisited, gray chains are on the current jump path (ancestors of the chain
// being processed), and black chains have been fully explored without being
// part of a cycle.
type chainColor int

const (
	chainWhite chainColor = iota
	chainGray
	chainBlack
)

// Validate checks every Jump rule in every chain of the table: the target
// must be a chain that exists in the table, and following Jump edges must
// never lead back to a chain already on the current path. Call it once all
// chains have been added — chains may reference each other regardless of add
// order (see AddChain), so this cannot be checked incrementally as rules or
// chains are added. Without calling Validate, a dangling jump target or a
// jump cycle is only discovered when a packet actually reaches that rule
// during Match/Evaluate (a cycle then fails safe via the jump depth limit in
// Chain.match rather than recursing forever).
func (t *Table) Validate() error {
	names := make([]string, 0, len(t.Chains))
	for name := range t.Chains {
		names = append(names, name)
	}
	sort.Strings(names)

	color := make(map[string]chainColor, len(names))

	var visit func(name string, path []string) error
	visit = func(name string, path []string) error {
		color[name] = chainGray
		path = append(path, name)
		for _, r := range t.Chains[name].Rules {
			if r.Action != Jump {
				continue
			}
			target := r.JumpTarget
			if _, ok := t.Chains[target]; !ok {
				return fmt.Errorf("chain %q: rule %q jumps to undefined chain %q", name, r.Name, target)
			}
			switch color[target] {
			case chainGray:
				cycle := strings.Join(append(path, target), " -> ")
				return fmt.Errorf("chain %q: rule %q creates a jump cycle: %s", name, r.Name, cycle)
			case chainWhite:
				if err := visit(target, path); err != nil {
					return err
				}
			}
		}
		color[name] = chainBlack
		return nil
	}

	for _, name := range names {
		if color[name] == chainWhite {
			if err := visit(name, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Table) Match(pkt *packet.Packet, result *Result) (bool, error) {
	if pkt == nil {
		return false, fmt.Errorf("nil packet")
	}
	if result == nil {
		return false, fmt.Errorf("nil result")
	}

	entry, ok := t.Chains[t.entryChain]
	if ok {
		matchResult, err := entry.match(pkt, result, t.Chains, 0)
		if err != nil {
			return false, err
		}
		switch matchResult {
		case chainDecided:
			return true, nil
		case chainPass:
			return false, nil
		}
	}
	// chainContinue: entry chain fell through
	return t.MatchDefaultRule(result), nil
}

func (t *Table) MatchDefaultRule(result *Result) bool {
	if t.DefaultRule != nil {
		t.DefaultRule.IncrementPacketCount()
		result.Trace = append(result.Trace, t.DefaultRule)
		if t.DefaultRule.Action.IsTerminal() {
			result.Verdict = &t.DefaultRule.Action
			return true
		}
		return false
	}
	return false
}

func SortTables(tables []*Table) {
	sort.SliceStable(tables, func(i, j int) bool {
		return tables[i].Order < tables[j].Order
	})
}

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
func NewChain(name string) *Chain {
	return &Chain{Name: name}
}

// AddRule inserts r into the chain, maintaining ascending order by Rule.Order.
func (c *Chain) AddRule(r *Rule) {
	i := sort.Search(len(c.Rules), func(i int) bool {
		return c.Rules[i].Order > r.Order
	})
	c.Rules = append(c.Rules, nil)
	copy(c.Rules[i+1:], c.Rules[i:])
	c.Rules[i] = r
}

// match evaluates the chain's rules against pkt.
//
// chains is the complete map of chains in the parent table, used to resolve
// Jump targets. depth counts the number of nested Jump calls taken to reach
// this chain (the entry chain is called with depth 0); it guards against jump
// cycles that Table.Validate wasn't run to catch. All evaluated rules
// (whether they match or not) are appended to result.Trace.
//
// Returns chainDecided if a terminal verdict (Accept/Drop) was set, chainPass
// if a Pass action was triggered, or chainContinue if evaluation should return
// to the calling context (Return action or no rule matched).
func (c *Chain) match(pkt *packet.Packet, result *Result, chains map[string]*Chain, depth int) (chainMatchResult, error) {
	if depth > MaxJumpDepth {
		return chainContinue, fmt.Errorf("jump depth exceeded %d at chain %q: possible jump cycle", MaxJumpDepth, c.Name)
	}
	var state conntrack.State
	if result.ConnState != nil {
		state = *result.ConnState
	}
	for _, r := range c.Rules {
		result.Trace = append(result.Trace, r)
		if r.MatchWithConntrackState(pkt, state) {
			switch r.Action {
			case Accept, Drop:
				result.Verdict = &r.Action
				return chainDecided, nil
			case Pass:
				result.Verdict = &r.Action
				return chainPass, nil
			case Return:
				return chainContinue, nil
			case Jump:
				target, ok := chains[r.JumpTarget]
				if !ok {
					return chainContinue, fmt.Errorf("chain %q not found", r.JumpTarget)
				}
				matchResult, err := target.match(pkt, result, chains, depth+1)
				if err != nil {
					return chainContinue, err
				}
				if matchResult != chainContinue {
					return matchResult, nil
				}
				// Target chain returned without a verdict; continue evaluating
				// the current chain at the next rule.
			}
		}
	}
	return chainContinue, nil
}
