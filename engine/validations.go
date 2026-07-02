package engine

import (
	"fmt"
)

func (e *Engine) Validate() []string {
	return e.validateAllRulesUsed()
}

func (e *Engine) validateAllRulesUsed() (o []string) {
	for _, t := range e.tables {
		for _, c := range t.Chains {
			for i, r := range c.Rules {
				if r.PacketCount() == 0 {
					o = append(o, fmt.Sprintf("Table %s Chain %s Rule %d not used", t.Name, c.Name, i))
				}
			}
		}
	}
	return
}
