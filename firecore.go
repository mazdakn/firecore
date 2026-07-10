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

func (e *Engine) Evaluate(ctx *eval.Context) (*eval.Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("evaluate: nil context")
	}
	if ctx.Packet == nil {
		return nil, fmt.Errorf("evaluate: nil packet")
	}

	result := &eval.Result{}
	if e.tracker != nil {
		state, err := e.tracker.Lookup(ctx.Packet)
		if err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
		ctx.ConnState = &state
	} else {
		ctx.ConnState = nil
	}
	decided := false
	for _, t := range e.Tables {
		matched, err := t.Match(ctx, result)
		if err != nil {
			return nil, fmt.Errorf("evaluate in table %q: %w", t.Name, err)
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
		if err := e.tracker.CommitAccepted(ctx.Packet); err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
	}

	return result, nil
}
