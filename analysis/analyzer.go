package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	analysismodule "github.com/ChrisMckerracher/cedar-go-wasm/internal/modules/analysis"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"time"
)

// Analyzer is safe for concurrent use; each call owns its instance and solver session.
type Analyzer struct {
	module          *wasmhost.Module
	solver          Solver
	timeout         time.Duration
	maxSourceBytes  int
	maxSolverOutput int64
}

// New enforces integrity and capability checks before any guest execution.
func New(ctx context.Context, solver Solver, opts ...Option) (*Analyzer, error) {
	if solver == nil {
		return nil, errors.New("analysis: nil solver")
	}
	cfg := config{
		timeout:         DefaultTimeout,
		memoryLimit:     DefaultMemoryLimitBytes,
		maxSourceBytes:  DefaultMaxSourceBytes,
		maxSolverOutput: DefaultMaxSolverOutput,
	}
	for _, o := range opts {
		o(&cfg)
	}
	m, err := wasmhost.Compile(ctx, wasmhost.Config{
		Name:             "analysis",
		Wasm:             analysismodule.Wasm,
		SHA256:           analysismodule.SHA256,
		MemoryLimitBytes: cfg.memoryLimit,
		Cache:            cfg.cache,
		AllowedImports:   analysisImports,
		HostModules:      defineHostModule,
		Exports:          []string{"cgw_analyze"},
	})
	if err != nil {
		return nil, fmt.Errorf("analysis: %w", err)
	}
	return &Analyzer{
		module:          m,
		solver:          solver,
		timeout:         cfg.timeout,
		maxSourceBytes:  cfg.maxSourceBytes,
		maxSolverOutput: cfg.maxSolverOutput,
	}, nil
}

func (a *Analyzer) Close(ctx context.Context) error { return a.module.Close(ctx) }

func ModuleSHA256() string { return analysismodule.SHA256 }

// NewlyPermitted holds when after permits nothing new; a counterexample is newly allowed.
// Both sets must pass strict validation against schema and contain no templates.
func (a *Analyzer) NewlyPermitted(ctx context.Context, schema cedar.Schema, before, after cedar.PolicySet) (Report, error) {
	// Reverse implication proves that after is a subset of before.
	return a.run(ctx, "implies", schema, after, before, true)
}

// Equivalent asks whether x and y give the same decision on every request.
// A counterexample is a request on which they differ.
func (a *Analyzer) Equivalent(ctx context.Context, schema cedar.Schema, x, y cedar.PolicySet) (Report, error) {
	return a.run(ctx, "equivalent", schema, x, y, false)
}

// NeverErrors checks one policy for evaluation errors on schema-valid requests.
func (a *Analyzer) NeverErrors(ctx context.Context, schema cedar.Schema, policy cedar.PolicySet) (Report, error) {
	return a.run(ctx, "never_errors", schema, policy, cedar.PolicySet{}, false)
}

// AlwaysMatches checks whether one policy matches every schema-valid request.
func (a *Analyzer) AlwaysMatches(ctx context.Context, schema cedar.Schema, policy cedar.PolicySet) (Report, error) {
	return a.run(ctx, "always_matches", schema, policy, cedar.PolicySet{}, false)
}

// NeverMatches checks whether one policy matches no schema-valid requests.
func (a *Analyzer) NeverMatches(ctx context.Context, schema cedar.Schema, policy cedar.PolicySet) (Report, error) {
	return a.run(ctx, "never_matches", schema, policy, cedar.PolicySet{}, false)
}

// MatchesEquivalent compares native matching behavior for permit and forbid policies.
func (a *Analyzer) MatchesEquivalent(ctx context.Context, schema cedar.Schema, x, y cedar.PolicySet) (Report, error) {
	return a.run(ctx, "matches_equivalent", schema, x, y, false)
}

// MatchesImplies checks whether matching x always implies matching y.
func (a *Analyzer) MatchesImplies(ctx context.Context, schema cedar.Schema, x, y cedar.PolicySet) (Report, error) {
	return a.run(ctx, "matches_implies", schema, x, y, false)
}

// MatchesDisjoint checks whether two policies can never both match one request.
func (a *Analyzer) MatchesDisjoint(ctx context.Context, schema cedar.Schema, x, y cedar.PolicySet) (Report, error) {
	return a.run(ctx, "matches_disjoint", schema, x, y, false)
}

// Disjoint checks whether two policy sets can never both allow one request.
func (a *Analyzer) Disjoint(ctx context.Context, schema cedar.Schema, x, y cedar.PolicySet) (Report, error) {
	return a.run(ctx, "disjoint", schema, x, y, false)
}

type analyzeInput struct {
	Schema wire.Source `json:"schema"`
	A      wire.Source `json:"a"`
	B      wire.Source `json:"b"`
	Query  string      `json:"query"`
}

type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("analysis: %s: %s", e.Kind, e.Message) }

func source(f cedar.Format, text string) wire.Source {
	return wire.Source{Format: f.String(), Text: text}
}

// swap restores the caller's argument order after a reversed implication query.
func (a *Analyzer) run(ctx context.Context, query string, schema cedar.Schema, pa, pb cedar.PolicySet, swap bool) (Report, error) {
	in, err := json.Marshal(analyzeInput{
		Schema: source(schema.Format(), schema.Text()),
		A:      source(pa.Format(), pa.Text()),
		B:      source(pb.Format(), pb.Text()),
		Query:  query,
	})
	if err != nil {
		return Report{}, &Error{Kind: string(cedar.KindInput), Message: err.Error()}
	}
	if len(in) > a.maxSourceBytes {
		return Report{}, fmt.Errorf("analysis: input is %d bytes, above the limit of %d", len(in), a.maxSourceBytes)
	}
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	session, err := a.solver.Start(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("analysis: %w", err)
	}
	state := &sessionState{session: session, limit: a.maxSolverOutput}
	defer session.Close()

	inst, err := a.module.Instantiate(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("analysis: %w", err)
	}
	defer inst.Close(context.WithoutCancel(ctx))
	out, err := inst.Call(context.WithValue(ctx, sessionKey{}, state), "cgw_analyze", in, defaultMaxResponseBytes)
	if err != nil {
		return Report{}, a.withSolverDetail(fmt.Errorf("analysis: %w", err), state, session)
	}
	var w analyzeOutput
	if err := json.Unmarshal(out, &w); err != nil {
		return Report{}, fmt.Errorf("analysis: decode response: %w", err)
	}
	if w.Error != nil {
		return Report{}, a.withSolverDetail(&Error{Kind: w.Error.Kind, Message: w.Error.Message}, state, session)
	}
	return decodePropertyReport(w, swap, query)
}

func (a *Analyzer) withSolverDetail(err error, state *sessionState, session Session) error {
	if state.err != nil {
		err = fmt.Errorf("%w (host: %v)", err, state.err)
	}
	if p, ok := session.(interface{ Stderr() string }); ok {
		if s := p.Stderr(); s != "" {
			err = fmt.Errorf("%w (solver stderr: %s)", err, s)
		}
	}
	return err
}
