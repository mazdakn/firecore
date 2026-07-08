package firecore

import (
	"fmt"

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

func (e *Engine) Evaluate(contexts []*eval.Context) ([]*eval.Result, error) {
	results := make([]*eval.Result, 0, len(contexts))

	for i, ctx := range contexts {
		if ctx == nil {
			return nil, fmt.Errorf("evaluate context %d: nil context", i)
		}
		if ctx.Packet == nil {
			return nil, fmt.Errorf("evaluate context %d: nil packet", i)
		}

		result := &eval.Result{}
		if e.tracker != nil {
			state := e.tracker.Lookup(ctx.Packet)
			ctx.ConnState = &state
		} else {
			ctx.ConnState = nil
		}
		decided := false
		for _, t := range e.Tables {
			matched, err := t.Match(ctx, result)
			if err != nil {
				return nil, fmt.Errorf("evaluate context %d in table %q: %w", i, t.Name, err)
			}
			if matched {
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
	return results, nil
}
