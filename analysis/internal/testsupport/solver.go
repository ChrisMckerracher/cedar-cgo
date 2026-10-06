package testsupport

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
)

type Solver func(context.Context) (solver.Session, error)

func (start Solver) Start(ctx context.Context) (solver.Session, error) { return start(ctx) }

type Transport struct {
	Closed     chan struct{}
	Closes     atomic.Int32
	WriteError error
	once       sync.Once
}

func (s *Transport) Read([]byte) (int, error) { <-s.Closed; return 0, io.EOF }

func (s *Transport) Write(data []byte) (int, error) {
	if s.WriteError != nil {
		return 0, s.WriteError
	}
	return len(data), nil
}

func (s *Transport) Close() error {
	s.once.Do(func() { s.Closes.Add(1); close(s.Closed) })
	return nil
}
