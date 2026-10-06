package execution

import (
	"github.com/ChrisMckerracher/cedar-cgo/internal/native"
	"github.com/jackc/puddle/v2"
)

func (a *Session) Finish(r *puddle.Resource[*native.Instance]) {
	if r.Value().Faulted() {
		a.discarded.Add(1)
		r.Destroy()
	} else {
		r.Release()
	}
}
func (a *Session) Close() { a.Pool.Close() }

type Stats struct {
	Created, Discarded uint64
	Idle               int
}

func (a *Session) Stats() Stats {
	return Stats{a.created.Load(), a.discarded.Load(), int(a.Pool.Stat().IdleResources())}
}
