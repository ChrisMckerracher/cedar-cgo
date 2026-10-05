package analysis

import "time"

const (
	DefaultTimeout          = 60 * time.Second
	DefaultMaxSourceBytes   = 64 << 20
	DefaultMaxSolverOutput  = 256 << 20
	defaultMaxResponseBytes = 256 << 20
)

type config struct {
	timeout         time.Duration
	maxSourceBytes  int
	maxSolverOutput int64
}

type Option func(*config)

// WithTimeout includes solver time. Cancellation closes solver I/O and rejects the result.
// Active native CPU work retains its resources until it returns.
func WithTimeout(duration time.Duration) Option { return func(c *config) { c.timeout = duration } }

// WithMaxSourceBytes caps both policy sets, the schema, and the JSON envelope.
func WithMaxSourceBytes(n int) Option { return func(c *config) { c.maxSourceBytes = n } }

// WithMaxSolverOutput caps the bytes that one call reads from the solver.
func WithMaxSolverOutput(n int64) Option { return func(c *config) { c.maxSolverOutput = n } }
