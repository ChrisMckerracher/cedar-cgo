package cedar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/modules/authorizer"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"github.com/tetratelabs/wazero"
)

// Default limits. Each one can be changed with an option or a [Limits] field.
const (
	DefaultMemoryLimitBytes = 256 << 20
	DefaultMaxSourceBytes   = 64 << 20
	DefaultMaxResponseBytes = 16 << 20
)

// authorizerImports lists every function the authorization module may
// import. Compilation fails if the module imports anything else.
var authorizerImports = []string{
	"wasi_snapshot_preview1.random_get",
	"wasi_snapshot_preview1.environ_get",
	"wasi_snapshot_preview1.environ_sizes_get",
	"wasi_snapshot_preview1.fd_write",
	"wasi_snapshot_preview1.proc_exit",
}

// Runtime holds the compiled authorization module. Compile it once per
// process and share it: it is safe for concurrent use.
type Runtime struct {
	module         *wasmhost.Module
	maxSourceBytes int
	maxResponse    uint32
}

type runtimeConfig struct {
	memoryLimit    uint64
	cache          wazero.CompilationCache
	maxSourceBytes int
}

// RuntimeOption configures [NewRuntime].
type RuntimeOption func(*runtimeConfig)

// WithMemoryLimit caps the linear memory of every module instance. A call
// that needs more memory faults, returns Deny, and its instance is
// discarded. The default is [DefaultMemoryLimitBytes].
func WithMemoryLimit(bytes uint64) RuntimeOption {
	return func(c *runtimeConfig) { c.memoryLimit = bytes }
}

// WithCompilationCache reuses compiled machine code across runtimes, for
// example from wazero.NewCompilationCacheWithDir. It cuts the startup cost
// of [NewRuntime] after the first run.
func WithCompilationCache(cache wazero.CompilationCache) RuntimeOption {
	return func(c *runtimeConfig) { c.cache = cache }
}

// WithMaxSourceBytes caps the size of the schema, policies and entities
// that one load or one validation sends to the module. The default is
// [DefaultMaxSourceBytes].
func WithMaxSourceBytes(n int) RuntimeOption {
	return func(c *runtimeConfig) { c.maxSourceBytes = n }
}

// NewRuntime verifies the SHA-256 of the embedded authorization module,
// checks its imports, and compiles it.
func NewRuntime(ctx context.Context, opts ...RuntimeOption) (*Runtime, error) {
	cfg := runtimeConfig{memoryLimit: DefaultMemoryLimitBytes, maxSourceBytes: DefaultMaxSourceBytes}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.maxSourceBytes <= 0 {
		return nil, fmt.Errorf("cedar: max source bytes must be positive, got %d", cfg.maxSourceBytes)
	}
	m, err := wasmhost.Compile(ctx, wasmhost.Config{
		Name:             "authorizer",
		Wasm:             authorizer.Wasm,
		SHA256:           authorizer.SHA256,
		MemoryLimitBytes: cfg.memoryLimit,
		Cache:            cfg.cache,
		AllowedImports:   authorizerImports,
		Exports:          []string{"cgw_load", "cgw_authorize", "cgw_validate"},
	})
	if err != nil {
		return nil, fmt.Errorf("cedar: %w", err)
	}
	return &Runtime{module: m, maxSourceBytes: cfg.maxSourceBytes, maxResponse: DefaultMaxResponseBytes}, nil
}

// Close releases the runtime and every instance it created. Authorizers
// created from it stop working.
func (rt *Runtime) Close(ctx context.Context) error {
	return rt.module.Close(ctx)
}

// ModuleSHA256 returns the hex SHA-256 of the embedded authorization module.
func ModuleSHA256() string { return authorizer.SHA256 }

// callOnce runs one operation on a fresh instance and closes it.
func (rt *Runtime) callOnce(ctx context.Context, op string, input []byte) ([]byte, error) {
	inst, err := rt.module.Instantiate(ctx)
	if err != nil {
		return nil, faultError(err)
	}
	defer inst.Close(context.WithoutCancel(ctx))
	out, err := inst.Call(ctx, op, input, rt.maxResponse)
	if err != nil {
		return nil, faultError(err)
	}
	return out, nil
}

// ValidationResult is the outcome of strict validation.
type ValidationResult struct {
	// Passed is true when the validator found no errors. Warnings do not
	// fail validation.
	Passed   bool
	Errors   []PolicyMessage
	Warnings []PolicyMessage
}

// PolicyMessage is a message about one policy.
type PolicyMessage struct {
	PolicyID string `json:"policy_id"`
	Message  string `json:"message"`
}

type validateInput struct {
	Schema   wire.Source `json:"schema"`
	Policies wire.Source `json:"policies"`
}

type validateOutput struct {
	Passed   *bool           `json:"passed"`
	Errors   []PolicyMessage `json:"errors"`
	Warnings []PolicyMessage `json:"warnings"`
	Error    *wire.Error     `json:"error"`
}

// Validate checks policies against a schema with Cedar's strict validator.
// It returns an [*Error] if the schema or the policies do not parse.
func (rt *Runtime) Validate(ctx context.Context, schema Schema, policies PolicySet) (ValidationResult, error) {
	in, err := json.Marshal(validateInput{Schema: schema.wire(), Policies: policies.wire()})
	if err != nil {
		return ValidationResult{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return ValidationResult{}, limitError("validation input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_validate", in)
	if err != nil {
		return ValidationResult{}, err
	}
	var resp validateOutput
	if err := json.Unmarshal(out, &resp); err != nil {
		return ValidationResult{}, faultError(fmt.Errorf("decode validation response: %w", err))
	}
	if resp.Error != nil {
		return ValidationResult{}, moduleError(resp.Error)
	}
	if resp.Passed == nil {
		return ValidationResult{}, faultError(fmt.Errorf("validation response has no result"))
	}
	return ValidationResult{Passed: *resp.Passed, Errors: resp.Errors, Warnings: resp.Warnings}, nil
}
