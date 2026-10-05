package analysis

import (
	"context"
	"errors"
)

type activeCall struct{ cancel context.CancelFunc }

func (a *Analyzer) beginCall(ctx context.Context) (context.Context, func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if a.closed {
		return nil, nil, errors.New("analysis: analyzer is closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	call := &activeCall{cancel: cancel}
	if a.active == nil {
		a.active = make(map[*activeCall]struct{})
	}
	a.active[call] = struct{}{}
	return ctx, func() {
		cancel()
		a.mu.Lock()
		delete(a.active, call)
		a.mu.Unlock()
	}, nil
}
