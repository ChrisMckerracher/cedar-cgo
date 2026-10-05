package native

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// Instance owns one native state. Call and Close serialize access to that state.
type Instance struct {
	module  *Module
	mu      sync.Mutex
	handle  uint64
	faulted atomic.Bool
	closing atomic.Bool
}

func (i *Instance) Faulted() bool { return i.faulted.Load() }
func (i *Instance) MarkFaulted()  { i.faulted.Store(true) }

// Close retains active-call resources until synchronous native execution returns.
func (i *Instance) Close(_ context.Context) error {
	i.closing.Store(true)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.handle == 0 {
		return nil
	}
	err := closeHandle(i.handle)
	i.handle = 0
	i.module.mu.Lock()
	delete(i.module.instances, i)
	i.module.mu.Unlock()
	return err
}

// Call borrows input during native execution and copies the owned response.
func (i *Instance) Call(ctx context.Context, operation string, input []byte, maxResponse uint32) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i.closing.Load() || i.handle == 0 || i.module.isClosed() {
		return nil, i.fault(operation, errors.New("instance is closed"))
	}
	if i.Faulted() {
		return nil, i.fault(operation, errors.New("instance is faulted"))
	}
	out, err := callHandle(ctx, i.handle, operation, input, maxResponse)
	if err != nil {
		return nil, i.fault(operation, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, i.fault(operation, err)
	}
	return out, nil
}

func (i *Instance) fault(operation string, err error) *Fault {
	i.MarkFaulted()
	return &Fault{Module: i.module.name, Op: operation, Err: err}
}
