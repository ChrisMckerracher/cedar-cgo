package analysis

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

type compiledTestTransport struct {
	closed chan struct{}
	once   sync.Once
	closes atomic.Int32
}

type compiledTestSolver func(context.Context) (Session, error)

func (start compiledTestSolver) Start(ctx context.Context) (Session, error) { return start(ctx) }

func (s *compiledTestTransport) Read([]byte) (int, error) { <-s.closed; return 0, io.EOF }

func (s *compiledTestTransport) Write(data []byte) (int, error) { return len(data), nil }

func (s *compiledTestTransport) Close() error {
	s.once.Do(func() { s.closes.Add(1); close(s.closed) })
	return nil
}

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

func testCompiledSession(t *testing.T, call func(context.Context, []byte) ([]byte, error)) (*CompiledSession, *compiledTestInstance, *compiledTestTransport) {
	t.Helper()
	lifetime, cancel := context.WithCancel(context.Background())
	transport := &compiledTestTransport{closed: make(chan struct{})}
	instance := &compiledTestInstance{call: call}
	a := &Analyzer{maxSourceBytes: 1 << 20, maxSolverOutput: 1 << 20, sessions: make(map[*CompiledSession]struct{})}
	s := &CompiledSession{analyzer: a, lifetime: lifetime, cancel: cancel, gate: make(chan struct{}, 1), done: make(chan struct{}), abortDone: make(chan struct{}), transport: transport, instance: instance, handles: map[uint64]struct{}{1: {}}, lastHandle: 1, environments: []RequestEnvironment{}}
	a.sessions[s] = struct{}{}
	t.Cleanup(func() { _ = s.Close() })
	return s, instance, transport
}
