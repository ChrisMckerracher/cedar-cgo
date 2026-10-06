package compiled

import (
	"context"
	"errors"
	"fmt"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/lifetime"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/settings"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/options"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	"github.com/ChrisMckerracher/cedar-cgo/internal/native"
	"github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// New opens a reusable session with constructor-context lifetime.
// A nil selection includes all environments. An empty selection includes none.
func New(ctx context.Context, transport solver.Solver, schema schemas.Schema, selection []RequestEnvironment, opts ...options.Option) (*Session, error) {
	if transport == nil {
		return nil, errors.New("analysis: nil solver")
	}
	cfg, err := settings.Apply(opts...)
	if err != nil {
		return nil, err
	}
	s := &Session{config: cfg, solver: transport}
	source := wire.Source{Format: schema.Format().String(), Text: schema.Text()}
	input := compiledInput{Operation: "open", Schema: &source}
	if selection != nil {
		selected := make([]compiledEnvironment, len(selection))
		for i, env := range selection {
			selected[i] = compiledEnvironment{env.PrincipalType, wire.UID{Type: env.Action.Type, ID: env.Action.ID}, env.ResourceType}
		}
		input.Environments = &selected
	}
	encoded, err := s.encodeCompiled(input)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	module, err := native.New(ctx, "analysis")
	if err != nil {
		return nil, fmt.Errorf("analysis: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	s.module, s.lifetime, s.cancel = module, sessionCtx, cancel
	s.gate, s.done, s.abortDone = make(chan struct{}, 1), make(chan struct{}), make(chan struct{})
	s.handles = make(map[uint64]struct{})
	context.AfterFunc(sessionCtx, func() { _ = s.closeWithReason(sessionCtx.Err()) })
	// Construction owns the same gate used by later calls.
	err = s.execute(ctx, encoded, nil, s.decodeOpen)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = errors.Join(ErrClosed, err)
		}
		return nil, &lifetime.Failure{Cause: err, Cleanup: s.closeWithReason(err)}
	}
	return s, nil
}

func (s *Session) initialize(ctx context.Context) error {
	if s.instance != nil {
		return nil
	}
	transport, err := s.solver.Start(s.lifetime)
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
	instance, err := s.module.Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("analysis: %w", err)
	}
	s.instance = instance
	return nil
}

// Environments returns a copy of the session's fixed native environment selection.
func (s *Session) Environments() []RequestEnvironment {
	return append([]RequestEnvironment{}, s.environments...)
}

func (s *Session) closedError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == nil || errors.Is(s.reason, ErrClosed) {
		return ErrClosed
	}
	return errors.Join(ErrClosed, s.reason)
}
