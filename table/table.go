package table

import (
	"fmt"
	"sort"

	"github.com/mazdakn/firecore/eval"
	"github.com/mazdakn/firecore/rule"
)

// Table holds chains of firewall rules. Rules are accessed only via chains;
// a Table must have at least one chain.
type Table struct {
	Name        string
	Order       uint64
	Chains      map[string]*Chain
	entryChain  string
	DefaultRule *rule.Rule
}

func New(name string, order uint64, defaultAction rule.Action) *Table {
	return &Table{
		Name:   name,
		Order:  order,
		Chains: make(map[string]*Chain),
		DefaultRule: rule.New(
			rule.WithAction(defaultAction),
			rule.WithName(fmt.Sprintf("table %s default action", name)),
		),
	}
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

func (t *Table) Match(ctx *eval.Context, result *eval.Result) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("nil context")
	}
	if ctx.Packet == nil {
		return false, fmt.Errorf("nil packet")
	}
	if result == nil {
		return false, fmt.Errorf("nil result")
	}

	entry, ok := t.Chains[t.entryChain]
	if ok {
		matchResult, err := entry.match(ctx, result, t.Chains)
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

func (t *Table) MatchDefaultRule(result *eval.Result) bool {
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
