// Package analysis compares Cedar policy sets with SymCC, Cedar's symbolic
// compiler, running in a WebAssembly module under wazero.
//
// SymCC turns each question into SMT-LIB queries. An external SMT solver,
// which you provide through a [Solver], answers them. Cedar supports cvc5;
// see [CVC5]. This module does not include a solver.
//
// Every counterexample that the solver returns is re-checked with Cedar's
// concrete authorizer inside the module, and the call fails if the check
// disagrees. A result that holds rests on the solver's "unsat" answer and
// on SymCC's encoding, which Cedar proves sound and complete in Lean.
package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm"
	analysismodule "github.com/ChrisMckerracher/cedar-go-wasm/internal/modules/analysis"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Defaults for [New].
const (
	DefaultTimeout          = 60 * time.Second
	DefaultMemoryLimitBytes = 1 << 30
	DefaultMaxSourceBytes   = 64 << 20
	DefaultMaxSolverOutput  = 256 << 20
	defaultMaxResponseBytes = 256 << 20
	hostModuleName          = "cgw_host"
	solverWriteFunction     = "solver_write"
	solverReadFunction      = "solver_read"
	solverReadChunk         = 1 << 16
)

// analysisImports lists every function the analysis module may import.
var analysisImports = []string{
	hostModuleName + "." + solverWriteFunction,
	hostModuleName + "." + solverReadFunction,
	"wasi_snapshot_preview1.random_get",
	"wasi_snapshot_preview1.environ_get",
	"wasi_snapshot_preview1.environ_sizes_get",
	"wasi_snapshot_preview1.clock_time_get",
	"wasi_snapshot_preview1.fd_write",
	"wasi_snapshot_preview1.poll_oneoff",
	"wasi_snapshot_preview1.proc_exit",
}

// Analyzer runs change analysis. It is safe for concurrent use; each call
// gets its own module instance and solver session.
type Analyzer struct {
	module          *wasmhost.Module
	solver          Solver
	timeout         time.Duration
	maxSourceBytes  int
	maxSolverOutput int64
}

type config struct {
	timeout         time.Duration
	memoryLimit     uint64
	cache           wazero.CompilationCache
	maxSourceBytes  int
	maxSolverOutput int64
}

// Option configures [New].
type Option func(*config)

// WithTimeout bounds each analysis call, solver time included. The default
// is [DefaultTimeout].
func WithTimeout(d time.Duration) Option { return func(c *config) { c.timeout = d } }

// WithMemoryLimit caps the linear memory of each module instance. The
// default is [DefaultMemoryLimitBytes].
func WithMemoryLimit(bytes uint64) Option { return func(c *config) { c.memoryLimit = bytes } }

// WithCompilationCache reuses compiled machine code across analyzers.
func WithCompilationCache(cache wazero.CompilationCache) Option {
	return func(c *config) { c.cache = cache }
}

// WithMaxSourceBytes caps the size of the schema and the two policy sets.
// The default is [DefaultMaxSourceBytes].
func WithMaxSourceBytes(n int) Option { return func(c *config) { c.maxSourceBytes = n } }

// WithMaxSolverOutput caps the bytes that one call reads from the solver.
// The default is [DefaultMaxSolverOutput].
func WithMaxSolverOutput(n int64) Option { return func(c *config) { c.maxSolverOutput = n } }

type sessionKey struct{}

// sessionState is the solver session of one call, which the host functions
// find through the call's context.
type sessionState struct {
	session Session
	read    int64
	limit   int64
	err     error
}

// New verifies the SHA-256 of the embedded analysis module, checks its
// imports and compiles it.
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

func defineHostModule(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder(hostModuleName).
		NewFunctionBuilder().WithFunc(solverWrite).Export(solverWriteFunction).
		NewFunctionBuilder().WithFunc(solverRead).Export(solverReadFunction).
		Instantiate(ctx)
	return err
}

// solverWrite copies guest bytes to the solver's input.
func solverWrite(ctx context.Context, m api.Module, ptr, n uint32) int32 {
	s, _ := ctx.Value(sessionKey{}).(*sessionState)
	if s == nil || s.err != nil {
		return -1
	}
	buf, ok := m.Memory().Read(ptr, n)
	if !ok {
		s.err = errors.New("solver input buffer out of range")
		return -1
	}
	if _, err := s.session.Write(buf); err != nil {
		s.err = fmt.Errorf("write to solver: %w", err)
		return -1
	}
	return 0
}

// solverRead copies solver output into guest memory. It returns the byte
// count, 0 at end of stream, or -1 on error.
func solverRead(ctx context.Context, m api.Module, ptr, n uint32) int32 {
	s, _ := ctx.Value(sessionKey{}).(*sessionState)
	if s == nil || s.err != nil {
		return -1
	}
	buf := make([]byte, min(n, solverReadChunk))
	k, err := s.session.Read(buf)
	if k > 0 {
		s.read += int64(k)
		if s.read > s.limit {
			s.err = fmt.Errorf("solver output exceeds %d bytes", s.limit)
			return -1
		}
		if !m.Memory().Write(ptr, buf[:k]) {
			s.err = errors.New("solver output buffer out of range")
			return -1
		}
		return int32(k)
	}
	if errors.Is(err, io.EOF) {
		return 0
	}
	if err != nil {
		s.err = fmt.Errorf("read from solver: %w", err)
	}
	return -1
}

// Close releases the analyzer.
func (a *Analyzer) Close(ctx context.Context) error { return a.module.Close(ctx) }

// ModuleSHA256 returns the hex SHA-256 of the embedded analysis module.
func ModuleSHA256() string { return analysismodule.SHA256 }

// Report holds one [Result] per request environment of the schema.
type Report struct {
	Results []Result
}

// Holds reports whether the property holds for every request environment.
func (r Report) Holds() bool {
	for _, res := range r.Results {
		if !res.Holds {
			return false
		}
	}
	return true
}

// Result is the answer for one request environment: one principal type,
// one action and one resource type from the schema.
type Result struct {
	PrincipalType string
	Action        cedar.EntityUID
	ResourceType  string
	// Holds is true when the solver proved the property for this
	// environment.
	Holds bool
	// Counterexample is set when Holds is false.
	Counterexample *Counterexample
}

// Counterexample is a concrete request on which the property fails.
type Counterexample struct {
	// Request carries the context and the entities of the counterexample.
	// It omits the schema's action entities.
	Request cedar.Request
	// Text describes the request in Cedar syntax.
	Text string
	// First and Second are the decisions of the first and the second policy
	// set argument on Request, from Cedar's authorizer.
	First, Second cedar.Decision
}

// NewlyPermitted asks whether after permits any request that before
// denies. The property holds for an environment when after permits nothing
// new there. A counterexample is a request that after allows and before
// denies.
//
// Both policy sets must pass strict validation against schema, and must
// not contain templates.
func (a *Analyzer) NewlyPermitted(ctx context.Context, schema cedar.Schema, before, after cedar.PolicySet) (Report, error) {
	// SymCC's implies(a, b): every request that a allows, b allows.
	return a.run(ctx, "implies", schema, after, before, true)
}

// Equivalent asks whether x and y give the same decision on every request.
// A counterexample is a request on which they differ.
func (a *Analyzer) Equivalent(ctx context.Context, schema cedar.Schema, x, y cedar.PolicySet) (Report, error) {
	return a.run(ctx, "equivalent", schema, x, y, false)
}

type analyzeInput struct {
	Schema wire.Source `json:"schema"`
	A      wire.Source `json:"a"`
	B      wire.Source `json:"b"`
	Query  string      `json:"query"`
}

type analyzeOutput struct {
	Results []struct {
		PrincipalType  string   `json:"principal_type"`
		Action         wire.UID `json:"action"`
		ResourceType   string   `json:"resource_type"`
		Holds          bool     `json:"holds"`
		Counterexample *struct {
			Request struct {
				Principal wire.UID        `json:"principal"`
				Action    wire.UID        `json:"action"`
				Resource  wire.UID        `json:"resource"`
				Context   json.RawMessage `json:"context"`
			} `json:"request"`
			Entities  json.RawMessage `json:"entities"`
			Text      string          `json:"text"`
			ADecision string          `json:"a_decision"`
			BDecision string          `json:"b_decision"`
		} `json:"counterexample"`
	} `json:"results"`
	Error *wire.Error `json:"error"`
}

// Error is an analysis error that the module reports, such as a policy
// that does not validate.
type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("analysis: %s: %s", e.Kind, e.Message) }

func source(f cedar.Format, text string) wire.Source {
	return wire.Source{Format: f.String(), Text: text}
}

func decision(s string) (cedar.Decision, error) {
	switch s {
	case "allow":
		return cedar.Allow, nil
	case "deny":
		return cedar.Deny, nil
	}
	return cedar.Deny, fmt.Errorf("analysis: module returned decision %q", s)
}

// run sends one query. swap is true when the wire order (a, b) is the
// reverse of the caller's argument order.
func (a *Analyzer) run(ctx context.Context, query string, schema cedar.Schema, pa, pb cedar.PolicySet, swap bool) (Report, error) {
	in, err := json.Marshal(analyzeInput{
		Schema: source(schema.Format(), schema.Text()),
		A:      source(pa.Format(), pa.Text()),
		B:      source(pb.Format(), pb.Text()),
		Query:  query,
	})
	if err != nil {
		return Report{}, err
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
	report := Report{Results: make([]Result, 0, len(w.Results))}
	for _, r := range w.Results {
		res := Result{
			PrincipalType: r.PrincipalType,
			Action:        cedar.NewEntityUID(r.Action.Type, r.Action.ID),
			ResourceType:  r.ResourceType,
			Holds:         r.Holds,
		}
		if c := r.Counterexample; c != nil {
			if r.Holds {
				return Report{}, errors.New("analysis: module returned a counterexample for a property that holds")
			}
			da, err := decision(c.ADecision)
			if err != nil {
				return Report{}, err
			}
			db, err := decision(c.BDecision)
			if err != nil {
				return Report{}, err
			}
			first, second := da, db
			if swap {
				first, second = db, da
			}
			res.Counterexample = &Counterexample{
				Request: cedar.Request{
					Principal: cedar.NewEntityUID(c.Request.Principal.Type, c.Request.Principal.ID),
					Action:    cedar.NewEntityUID(c.Request.Action.Type, c.Request.Action.ID),
					Resource:  cedar.NewEntityUID(c.Request.Resource.Type, c.Request.Resource.ID),
					Context:   cedar.ContextFromJSON(c.Request.Context),
					Entities:  cedar.EntitiesFromJSON(c.Entities),
				},
				Text:   c.Text,
				First:  first,
				Second: second,
			}
		} else if !r.Holds {
			return Report{}, errors.New("analysis: module returned a failed property without a counterexample")
		}
		report.Results = append(report.Results, res)
	}
	return report, nil
}

// withSolverDetail adds the host-side solver error and the solver's stderr
// to err.
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
