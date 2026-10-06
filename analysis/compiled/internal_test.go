package compiled

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/settings"
	fixtures "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/testsupport"
)

type compiledTestInstance struct {
	calls  atomic.Int32
	closes atomic.Int32
	call   func(context.Context, []byte) ([]byte, error)
}

func (i *compiledTestInstance) Call(ctx context.Context, _ string, input []byte, _ uint32) ([]byte, error) {
	i.calls.Add(1)
	return i.call(ctx, input)
}

func (i *compiledTestInstance) Close(context.Context) error { i.closes.Add(1); return nil }

func testSession(t *testing.T, call func(context.Context, []byte) ([]byte, error)) (*Session, *compiledTestInstance, *fixtures.Transport) {
	t.Helper()
	lifetime, cancel := context.WithCancel(context.Background())
	transport := &fixtures.Transport{Closed: make(chan struct{})}
	instance := &compiledTestInstance{call: call}
	s := &Session{config: settings.Config{MaxSourceBytes: 1 << 20, MaxSolverOutput: 1 << 20}, lifetime: lifetime, cancel: cancel, gate: make(chan struct{}, 1), done: make(chan struct{}), abortDone: make(chan struct{}), transport: transport, instance: instance, handles: map[uint64]struct{}{1: {}}, lastHandle: 1, environments: []RequestEnvironment{}}
	t.Cleanup(func() { _ = s.Close() })
	return s, instance, transport
}
