package firecore

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
)

type Option func(*Engine)

func WithNoConnTrack() Option {
	return func(e *Engine) {
		e.ConntrackEnabled = false
	}
}

type Engine struct {
	Tables []*table.Table

	ConntrackEnabled bool
}

func New(tables []*table.Table, opts ...Option) *Engine {
	engine := &Engine{
		Tables:           []*table.Table{},
		ConntrackEnabled: true,
	}
	if tables != nil {
		engine.Tables = tables
	}
	for _, opt := range opts {
		opt(engine)
	}
	return engine
}

func (e *Engine) Run(contexts []*match.MatchContext) []*match.MatchContext {
	results := make([]*match.MatchContext, 0, len(contexts))

	var tracker *conntrack.Tracker
	if e.ConntrackEnabled {
		tracker = conntrack.NewTracker()
	}
	for _, mc := range contexts {
		if e.ConntrackEnabled {
			mc.ConnState = tracker.Lookup(mc.Packet)
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
		if e.ConntrackEnabled && mc.Verdict != nil && *mc.Verdict == rule.Accept {
			tracker.CommitAccepted(mc.Packet)
		}
		results = append(results, mc)
	}
	return results
}
