package analysis

import (
	"context"
	"errors"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/compiled"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/lifetime"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/settings"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/options"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

// OpenCompiled registers construction before opening child native resources.
func (a *Analyzer) OpenCompiled(ctx context.Context, schema schemas.Schema, selection []compiled.RequestEnvironment) (*compiled.Session, error) {
	lease, err := a.owner.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifetime.ErrClosed) {
			return nil, compiled.ErrClosed
		}
		return nil, err
	}
	child, err := compiled.New(lease.Context, a.solver, schema, selection,
		options.WithTimeout(a.config.Timeout), options.WithMaxSourceBytes(a.config.MaxSourceBytes), options.WithMaxSolverOutput(a.config.MaxSolverOutput),
		func(cfg *settings.Config) { cfg.OnClosed = lease.Release })
	if err != nil {
		lease.Finish(lifetime.Cleanup(err))
		return nil, err
	}
	lease.Keep(child)
	return child, nil
}
