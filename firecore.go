package firecore

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/eval"
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

func (e *Engine) Evaluate(contexts []*eval.Context) []*eval.Result {
	results := make([]*eval.Result, 0, len(contexts))

	for _, ctx := range contexts {
		result := &eval.Result{}
		if e.tracker != nil {
			state := e.tracker.Lookup(ctx.Packet)
			ctx.ConnState = &state
		} else {
			ctx.ConnState = nil
		}
		decided := false
		for _, t := range e.Tables {
			if t.Match(ctx, result) {
				decided = true
				break
			}
		}
		if !decided {
			result.Verdict = nil
		}
		if e.tracker != nil && result.Verdict != nil && *result.Verdict == rule.Accept {
			e.tracker.CommitAccepted(ctx.Packet)
		}
		results = append(results, result)
	}
	return results
}
