package cedar

import (
	"context"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/modules/authorizer"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
	"github.com/tetratelabs/wazero"
)

const (
	DefaultMemoryLimitBytes = 256 << 20
	DefaultMaxSourceBytes   = 64 << 20
	DefaultMaxResponseBytes = 16 << 20
)

// Reject unlisted imports so guest upgrades cannot silently gain host capabilities.
var authorizerImports = []string{
	"cgw_entity_loader.load",
	"cgw_entity_loader.read",
	"wasi_snapshot_preview1.random_get",
	"wasi_snapshot_preview1.environ_get",
	"wasi_snapshot_preview1.environ_sizes_get",
	"wasi_snapshot_preview1.fd_write",
	"wasi_snapshot_preview1.proc_exit",
}

// Runtime is safe to share across goroutines to amortize module compilation.
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

type RuntimeOption func(*runtimeConfig)

// WithMemoryLimit caps per-instance linear memory; exceeding it faults and discards
// the instance. The default is [DefaultMemoryLimitBytes].
func WithMemoryLimit(bytes uint64) RuntimeOption {
	return func(c *runtimeConfig) { c.memoryLimit = bytes }
}

// WithCompilationCache avoids recompilation across runtimes and, with a disk cache, restarts.
func WithCompilationCache(cache wazero.CompilationCache) RuntimeOption {
	return func(c *runtimeConfig) { c.cache = cache }
}

// WithMaxSourceBytes bounds each encoded load, validation or slicing input, including its envelope.
// The default is [DefaultMaxSourceBytes].
func WithMaxSourceBytes(n int) RuntimeOption {
	return func(c *runtimeConfig) { c.maxSourceBytes = n }
}

// NewRuntime enforces integrity and capability checks before any guest execution.
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
		HostModules:      defineEntityLoaderModule,
		Exports:          []string{"cgw_load", "cgw_authorize", "cgw_validate", "cgw_authorize_batched", "cgw_slice_entities"},
	})
	if err != nil {
		return nil, fmt.Errorf("cedar: %w", err)
	}
	return &Runtime{module: m, maxSourceBytes: cfg.maxSourceBytes, maxResponse: DefaultMaxResponseBytes}, nil
}

// Close also invalidates every authorizer created from this runtime.
func (rt *Runtime) Close(ctx context.Context) error {
	return rt.module.Close(ctx)
}

func ModuleSHA256() string { return authorizer.SHA256 }
