// Package native owns synchronous cgo execution and native handle lifetimes.
package native

import (
	"context"
	"errors"
	"sync"
)

const ABIVersion = 2

// Module owns every instance that it creates.
type Module struct {
	name      string
	mu        sync.Mutex
	closed    bool
	instances map[*Instance]struct{}
}

// New checks the linked interface before creating native state.
func New(ctx context.Context, name string) (*Module, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name != "authorizer" && name != "analysis" {
		return nil, errors.New("native: unknown module")
	}
	if err := checkABI(); err != nil {
		return nil, err
	}
	return &Module{name: name, instances: make(map[*Instance]struct{})}, nil
}

func (m *Module) Instantiate(ctx context.Context) (*Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.closed {
		return nil, errors.New("native: module is closed")
	}
	handle, err := newHandle(m.name)
	if err != nil {
		return nil, err
	}
	i := &Instance{module: m, handle: handle}
	m.instances[i] = struct{}{}
	return i, nil
}

func (m *Module) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// Close rejects new calls, waits for active calls, and releases native state.
func (m *Module) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	instances := make([]*Instance, 0, len(m.instances))
	for instance := range m.instances {
		instances = append(instances, instance)
	}
	m.mu.Unlock()
	var errs []error
	for _, instance := range instances {
		errs = append(errs, instance.Close(ctx))
	}
	return errors.Join(errs...)
}
