package analysis

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/lifetime"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/settings"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/options"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
	"github.com/ChrisMckerracher/cedar-cgo/internal/native"
)

// Analyzer owns stateless calls and child compiled sessions.
type Analyzer struct {
	module    *native.Module
	solver    solver.Solver
	config    settings.Config
	owner     lifetime.Owner
	closeOnce sync.Once
	closeErr  error
}

// New checks the native ABI before starting a solver session.
func New(ctx context.Context, transport solver.Solver, opts ...options.Option) (*Analyzer, error) {
	if transport == nil {
		return nil, errors.New("analysis: nil solver")
	}
	cfg, err := settings.Apply(opts...)
	if err != nil {
		return nil, err
	}
	module, err := native.New(ctx, "analysis")
	if err != nil {
		return nil, fmt.Errorf("analysis: %w", err)
	}
	return &Analyzer{module: module, solver: transport, config: cfg}, nil
}

// Close cancels calls and child sessions before freeing native state.
func (a *Analyzer) Close(ctx context.Context) error {
	a.closeOnce.Do(func() {
		a.closeErr = a.owner.Close()
		if a.module != nil {
			a.closeErr = errors.Join(a.closeErr, a.module.Close(ctx))
		}
	})
	return a.closeErr
}
