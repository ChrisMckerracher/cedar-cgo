package analysis

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
)

// Analyzer supports concurrent stateless calls and explicitly owned compiled sessions.
type Analyzer struct {
	module          *native.Module
	solver          solver.Solver
	timeout         time.Duration
	maxSourceBytes  int
	maxSolverOutput int64
	mu              sync.Mutex
	sessions        map[*CompiledSession]struct{}
	active          map[*activeCall]struct{}
	closed          bool
	closeOnce       sync.Once
	closeErr        error
}

// New checks the native ABI before starting any solver session.
func New(ctx context.Context, transport solver.Solver, opts ...Option) (*Analyzer, error) {
	if transport == nil {
		return nil, errors.New("analysis: nil solver")
	}
	cfg := config{timeout: DefaultTimeout, maxSourceBytes: DefaultMaxSourceBytes, maxSolverOutput: DefaultMaxSolverOutput}
	for _, option := range opts {
		option(&cfg)
	}
	if cfg.maxSourceBytes <= 0 || cfg.maxSolverOutput <= 0 {
		return nil, errors.New("analysis: source and solver output limits must be positive")
	}
	module, err := native.New(ctx, "analysis")
	if err != nil {
		return nil, fmt.Errorf("analysis: %w", err)
	}
	return &Analyzer{module: module, solver: transport, timeout: cfg.timeout, maxSourceBytes: cfg.maxSourceBytes, maxSolverOutput: cfg.maxSolverOutput}, nil
}

// Close cancels compiled sessions and waits for active native calls before freeing state.
func (a *Analyzer) Close(ctx context.Context) error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		active := make([]*activeCall, 0, len(a.active))
		for call := range a.active {
			active = append(active, call)
		}
		sessions := make([]*CompiledSession, 0, len(a.sessions))
		for session := range a.sessions {
			sessions = append(sessions, session)
		}
		a.mu.Unlock()
		for _, call := range active {
			call.cancel()
		}
		for _, session := range sessions {
			a.closeErr = errors.Join(a.closeErr, session.Close())
		}
		if a.module != nil {
			a.closeErr = errors.Join(a.closeErr, a.module.Close(ctx))
		}
	})
	return a.closeErr
}
