package analysis

import (
	"context"
	"errors"
	"fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// OpenCompiled creates a reusable session tied to the constructor context.
// A nil selection includes all environments. An empty selection includes none.
func (a *Analyzer) OpenCompiled(ctx context.Context, schema cedar.Schema, selection []RequestEnvironment) (*CompiledSession, error) {
	source := source(schema.Format(), schema.Text())
	input := compiledInput{Operation: "open", Schema: &source}
	if selection != nil {
		selected := make([]compiledEnvironment, len(selection))
		for i, env := range selection {
			selected[i] = compiledEnvironment{env.PrincipalType, wire.UID{Type: env.Action.Type, ID: env.Action.ID}, env.ResourceType}
		}
		input.Environments = &selected
	}
	encoded, err := a.encodeCompiled(input)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	s := &CompiledSession{analyzer: a, lifetime: lifetime, cancel: cancel, gate: make(chan struct{}, 1), done: make(chan struct{}), abortDone: make(chan struct{}), handles: make(map[uint64]struct{})}
	// Register before starting resources so Analyzer.Close can cancel construction.
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		cancel()
		return nil, ErrCompiledClosed
	}
	if a.sessions == nil {
		a.sessions = make(map[*CompiledSession]struct{})
	}
	a.sessions[s] = struct{}{}
	a.mu.Unlock()
	context.AfterFunc(lifetime, func() { _ = s.closeWithReason(lifetime.Err()) })
	// Construction owns the same gate used by later calls.
	err = s.execute(ctx, encoded, nil, s.decodeOpen)
	if err != nil {
		return nil, errors.Join(err, s.closeWithReason(err))
	}
	return s, nil
}

func (s *CompiledSession) initialize(ctx context.Context) error {
	if s.instance != nil {
		return nil
	}
	transport, err := s.analyzer.solver.Start(s.lifetime)
	if err != nil {
		return fmt.Errorf("analysis: %w", err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeErr := transport.Close()
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, closeErr)
		s.mu.Unlock()
		return s.closedError()
	}
	s.transport = transport
	s.mu.Unlock()
	instance, err := s.analyzer.module.Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("analysis: %w", err)
	}
	s.instance = instance
	return nil
}

// Environments returns a copy of the session's fixed native environment selection.
func (s *CompiledSession) Environments() []RequestEnvironment {
	return append([]RequestEnvironment{}, s.environments...)
}

func (s *CompiledSession) closedError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == nil || errors.Is(s.reason, ErrCompiledClosed) {
		return ErrCompiledClosed
	}
	return errors.Join(ErrCompiledClosed, s.reason)
}
