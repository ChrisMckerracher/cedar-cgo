package analysis

import (
	"github.com/tetratelabs/wazero"
	"time"
)

const (
	DefaultTimeout          = 60 * time.Second
	DefaultMemoryLimitBytes = 1 << 30
	DefaultMaxSourceBytes   = 64 << 20
	DefaultMaxSolverOutput  = 256 << 20
	defaultMaxResponseBytes = 256 << 20
)

type config struct {
	timeout         time.Duration
	memoryLimit     uint64
	cache           wazero.CompilationCache
	maxSourceBytes  int
	maxSolverOutput int64
}

type Option func(*config)

// WithTimeout includes solver time; the default is [DefaultTimeout].
func WithTimeout(d time.Duration) Option { return func(c *config) { c.timeout = d } }

// WithMemoryLimit caps per-instance linear memory; the default is [DefaultMemoryLimitBytes].
func WithMemoryLimit(bytes uint64) Option { return func(c *config) { c.memoryLimit = bytes } }

// WithCompilationCache avoids recompilation across analyzers.
func WithCompilationCache(cache wazero.CompilationCache) Option {
	return func(c *config) { c.cache = cache }
}

// WithMaxSourceBytes includes both policy sets, the schema and the JSON envelope.
// The default is [DefaultMaxSourceBytes].
func WithMaxSourceBytes(n int) Option { return func(c *config) { c.maxSourceBytes = n } }

// WithMaxSolverOutput caps the bytes that one call reads from the solver.
// The default is [DefaultMaxSolverOutput].
func WithMaxSolverOutput(n int64) Option { return func(c *config) { c.maxSolverOutput = n } }
