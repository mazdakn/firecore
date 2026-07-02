package firecore

import (
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
)

type Option func(*Engine)

func WithTables(tables []*table.Table) Option {
	return func(e *Engine) {
		e.Tables = tables
	}
}

func WithNoConnTrack() Option {
	return func(e *Engine) {
		e.ConntrackEnabled = false
	}
}

type Engine struct {
	Tables []*table.Table

	ConntrackEnabled bool
}

func New(opts ...Option) *Engine {
	engine := &Engine{
		ConntrackEnabled: true,
	}
	for _, opt := range opts {
		opt(engine)
	}
	return engine
}

func (e *Engine) Run(mc []*match.MatchContext) []*match.MatchContext {
	results := make([]*match.MatchContext, 0, len(mc))

	var tracker *conntrack.Tracker
	if e.ConntrackEnabled {
		tracker = conntrack.NewTracker()
	}
	for _, mc := range mc {
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
