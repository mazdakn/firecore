package firecore

import (
	"fmt"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/eval"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/rule"
)

type Option func(*Engine)

func WithConntrack() Option {
	return func(e *Engine) {
		e.tracker = conntrack.NewTracker()
	}
}

type Engine struct {
	Tables []*Table

	tracker *conntrack.Tracker
}

func New(opts ...Option) *Engine {
	engine := &Engine{}
	for _, opt := range opts {
		opt(engine)
	}
	return engine
}

func (e *Engine) AddTable(t *Table) {
	e.Tables = append(e.Tables, t)
	SortTables(e.Tables)
}

func (e *Engine) Evaluate(pkt *packet.Packet) (*eval.Result, error) {
	if pkt == nil {
		return nil, fmt.Errorf("evaluate: nil packet")
	}

	result := &eval.Result{}
	if e.tracker != nil {
		state, err := e.tracker.Lookup(pkt)
		if err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
		result.ConnState = &state
	}
	decided := false
	for _, t := range e.Tables {
		matched, err := t.Match(pkt, result)
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
		if err := e.tracker.CommitAccepted(pkt); err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
	}

	return result, nil
}
