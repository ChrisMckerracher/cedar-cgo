// Package options configures stateless and compiled analysis limits.
package options

import (
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/settings"
)

const (
	DefaultTimeout         = settings.DefaultTimeout
	DefaultMaxSourceBytes  = settings.DefaultMaxSourceBytes
	DefaultMaxSolverOutput = settings.DefaultMaxSolverOutput
)

type Option = settings.Option

// WithTimeout includes solver time. Cancellation closes solver I/O and rejects the result.
func WithTimeout(duration time.Duration) Option {
	return func(c *settings.Config) { c.Timeout = duration }
}

// WithMaxSourceBytes caps policy sets, the schema, and the JSON envelope.
func WithMaxSourceBytes(n int) Option { return func(c *settings.Config) { c.MaxSourceBytes = n } }

// WithMaxSolverOutput caps bytes read from the solver during one call.
func WithMaxSolverOutput(n int64) Option { return func(c *settings.Config) { c.MaxSolverOutput = n } }
