package firecore

import (
	"fmt"

	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/packet"
)

// Result is the outcome of evaluating a packet with Engine.Evaluate.
type Result struct {
	// Verdict is the final decision (Accept or Drop), or Undecided if no table
	// reached a terminal verdict.
	Verdict Action
	// Trace lists every rule inspected during evaluation, in the order
	// evaluated, regardless of whether each one matched.
	Trace []*Rule
	// ConnState is the connection state the packet was classified as by
	// the engine's conntrack tracker, or nil if conntrack is disabled.
	ConnState *conntrack.State
}

type Option func(*Engine) error

func WithConntrack() Option {
	return func(e *Engine) error {
		e.tracker = conntrack.NewTracker()
		return nil
	}
}

type Engine struct {
	Tables []*Table

	tracker *conntrack.Tracker
}

func New(opts ...Option) (*Engine, error) {
	engine := &Engine{}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("engine option must not be nil")
		}
		if err := opt(engine); err != nil {
			return nil, err
		}
	}
	return engine, nil
}

func (e *Engine) AddTable(t *Table) error {
	if t == nil {
		return fmt.Errorf("table must not be nil")
	}
	e.Tables = append(e.Tables, t)
	SortTables(e.Tables)
	return nil
}

func (e *Engine) Evaluate(pkt *packet.Packet) (*Result, error) {
	if pkt == nil {
		return nil, fmt.Errorf("evaluate: nil packet")
	}

	result := &Result{}
	state := conntrack.StateNew
	if e.tracker != nil {
		lookedUp, err := e.tracker.Lookup(pkt)
		if err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
		state = lookedUp
		result.ConnState = &state
	}
	for _, t := range e.Tables {
		verdict, err := t.match(pkt, state, result)
		if err != nil {
			return nil, fmt.Errorf("evaluate in table %q: %w", t.Name, err)
		}
		if verdict.IsTerminal() {
			break
		}
	}
	if e.tracker != nil && result.Verdict == Accept {
		if err := e.tracker.CommitAccepted(pkt); err != nil {
			return nil, fmt.Errorf("evaluate: %w", err)
		}
	}

	return result, nil
}
