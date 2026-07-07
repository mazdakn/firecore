package table

import (
	"fmt"
	"sort"

	"github.com/mazdakn/firecore/eval"
	"github.com/mazdakn/firecore/rule"
	"github.com/sirupsen/logrus"
)

// Table holds chains of firewall rules. Rules are accessed only via chains;
// a Table must have at least one chain.
type Table struct {
	Name        string
	Order       uint64
	Chains      map[string]*Chain
	entryChain  string
	DefaultRule *rule.Rule
	logCtx      *logrus.Entry
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
		logCtx: logrus.WithFields(logrus.Fields{
			"name":          name,
			"defaultAction": defaultAction,
		}),
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

func (t *Table) Match(ctx *eval.Context, result *eval.Result) bool {
	t.logCtx.Debugf("Matching packet %+v", ctx.Packet)
	entry, ok := t.Chains[t.entryChain]
	if ok {
		matchResult := entry.match(ctx, result, t.Chains)
		switch matchResult {
		case chainDecided:
			t.logCtx.Debugf("Chain determined verdict %s", result.Verdict)
			return true
		case chainPass:
			t.logCtx.Debugf("Chain pass action, continuing to next table")
			return false
		}
	}
	// chainContinue: entry chain fell through
	return t.MatchDefaultRule(result)
}

func (t *Table) MatchDefaultRule(result *eval.Result) bool {
	if t.DefaultRule != nil {
		t.logCtx.Debugf("No rule matched, using default action %v", t.DefaultRule.Action)
		t.DefaultRule.IncrementPacketCount()
		result.Trace = append(result.Trace, t.DefaultRule)
		if t.DefaultRule.Action.IsTerminal() {
			result.Verdict = &t.DefaultRule.Action
			return true
		}
		return false
	}
	t.logCtx.Debugf("No rule matched and no default rule set")
	return false
}

func SortTables(tables []*Table) {
	sort.SliceStable(tables, func(i, j int) bool {
		return tables[i].Order < tables[j].Order
	})
}
