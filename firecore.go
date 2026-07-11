package firecore

import (
	"fmt"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
	"github.com/mazdakn/firecore/rule"
)

// Result is the outcome of evaluating a packet with Engine.Evaluate.
type Result struct {
	// Verdict is the final decision, or nil if no table decided.
	Verdict *rule.Action
	// Trace lists every rule inspected during evaluation, in the order
	// evaluated, regardless of whether each one matched.
	Trace []*rule.Rule
	// ConnState is the connection state the packet was classified as by
	// the engine's conntrack tracker, or nil if conntrack is disabled.
	ConnState *conntrack.State
}

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

func (e *Engine) Evaluate(pkt *packet.Packet) (*Result, error) {
	if pkt == nil {
		return nil, fmt.Errorf("evaluate: nil packet")
	}

	result := &Result{}
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
