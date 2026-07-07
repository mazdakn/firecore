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

func (e *Engine) Evaluate(contexts []*eval.Context) []*eval.Context {
	results := make([]*eval.Context, 0, len(contexts))

	for _, ctx := range contexts {
		if e.tracker != nil {
			state := e.tracker.Lookup(ctx.Packet)
			ctx.ConnState = &state
		}
		decided := false
		for _, t := range e.Tables {
			if t.Match(ctx) {
				decided = true
				break
			}
		}
		if !decided {
			ctx.Verdict = nil
		}
		if e.tracker != nil && ctx.Verdict != nil && *ctx.Verdict == rule.Accept {
			e.tracker.CommitAccepted(ctx.Packet)
		}
		results = append(results, ctx)
	}
	return results
}
