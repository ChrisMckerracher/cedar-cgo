package cedar

import (
	"context"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/modules/authorizer"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
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
