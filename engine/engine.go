package engine

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
)

type Engine struct {
	tables []*table.Table
}

func New(tables []*table.Table) *Engine {
	if tables != nil {
		return &Engine{tables: tables}
	}
	return &Engine{tables: []*table.Table{}}
}

func (e *Engine) Run(contexts []*match.MatchContext) []*match.MatchContext {
	results := make([]*match.MatchContext, 0, len(contexts))
	tracker := conntrack.NewTracker()
	for _, mc := range contexts {
		mc.ConnState = tracker.Lookup(mc.Packet)
		decided := false
		for _, t := range e.tables {
			if t.Match(mc) {
				decided = true
				break
			}
		}
		if !decided {
			mc.Verdict = nil
		}
		if mc.Verdict != nil && *mc.Verdict == rule.Accept {
			tracker.CommitAccepted(mc.Packet)
		}
		results = append(results, mc)
	}
	return results
}
