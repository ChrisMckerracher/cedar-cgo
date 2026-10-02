package analysis

import (
	"github.com/tetratelabs/wazero"
	"time"
)

// Defaults for [New].
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
