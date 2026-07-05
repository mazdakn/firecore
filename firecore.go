package firecore

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
)

type Option func(*Engine)

func WithConntrack() Option {
	return func(e *Engine) {
		e.tracker = conntrack.NewTracker()
	}
}

type Engine struct {
	Tables []*table.Table

	tracker *conntrack.Tracker
}

func New(opts ...Option) *Engine {
	engine := &Engine{}
	for _, opt := range opts {
		opt(engine)
	}
	return engine
}

func (e *Engine) AddTable(t *table.Table) {
	e.Tables = append(e.Tables, t)
	table.SortTables(e.Tables)
}

func (e *Engine) Evaluate(mc []*match.MatchContext) []*match.MatchContext {
	results := make([]*match.MatchContext, 0, len(mc))

	for _, mc := range mc {
		if e.tracker != nil {
			mc.ConnState = e.tracker.Lookup(mc.Packet)
		}
		decided := false
		for _, t := range e.Tables {
			if t.Match(mc) {
				decided = true
				break
			}
		}
		if !decided {
			mc.Verdict = nil
		}
		if e.tracker != nil && mc.Verdict != nil && *mc.Verdict == rule.Accept {
			e.tracker.CommitAccepted(mc.Packet)
		}
		results = append(results, mc)
	}
	return results
}
