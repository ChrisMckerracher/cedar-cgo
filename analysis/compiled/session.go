package compiled

import (
	"context"
	"errors"
	"sync"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/settings"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
)

var ErrClosed = errors.New("analysis: compiled session is closed")

type compiledInstance interface {
	Call(context.Context, string, []byte, uint32) ([]byte, error)
	Close(context.Context) error
}

// Session reuses native compilation and one solver transport.
// Calls are serialized. Close releases all handles, native state, and the solver.
type Session struct {
	module      *native.Module
	solver      solver.Solver
	config      settings.Config
	releaseOnce sync.Once
	lifetime    context.Context
	cancel      context.CancelFunc
	gate        chan struct{}
	done        chan struct{}
	abortDone   chan struct{}
	mu          sync.Mutex
	closed      bool
	reason      error
	transport   solver.Session
	closeErr    error
	// The gate protects native access and the active handle map.
	instance     compiledInstance
	handles      map[uint64]struct{}
	environments []RequestEnvironment
	lastHandle   uint64
}
