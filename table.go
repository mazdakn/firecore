package firecore

import (
	"fmt"
	"sort"
	"strings"

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
	if name == "" {
		return nil, fmt.Errorf("table name must not be empty")
	}

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
// unless SetEntryChain is called explicitly. It is an error for c to be nil,
// have an empty name, or share its name with a chain already in the table.
func (t *Table) AddChain(c *Chain) error {
	if c == nil {
		return fmt.Errorf("chain must not be nil")
	}
	if c.Name == "" {
		return fmt.Errorf("chain name must not be empty")
	}
	if _, exists := t.Chains[c.Name]; exists {
		return fmt.Errorf("chain %q already exists in table %q", c.Name, t.Name)
	}

	t.Chains[c.Name] = c
	if t.entryChain == "" {
		t.entryChain = c.Name
	}
	return nil
}

// SetEntryChain designates the named chain as the entry point for packet
// evaluation. name must refer to a chain already added via AddChain.
func (t *Table) SetEntryChain(name string) error {
	if _, ok := t.Chains[name]; !ok {
		return fmt.Errorf("chain %q not found in table %q", name, t.Name)
	}
	t.entryChain = name
	return nil
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
