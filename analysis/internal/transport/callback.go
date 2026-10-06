package transport

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
)

const solverReadChunk = 1 << 16

// Each native call owns its solver buffers, output limit, and callback errors.
type State struct {
	session solver.Session
	read    int64
	limit   int64
	err     error
}

func New(session solver.Session, limit int64) *State {
	return &State{session: session, limit: limit}
}

func (s *State) Err() error { return s.err }

func (s *State) Detail(err error) error {
	if s.err != nil {
		err = fmt.Errorf("%w (host: %v)", err, s.err)
	}
	if p, ok := s.session.(interface{ Stderr() string }); ok {
		if detail := p.Stderr(); detail != "" {
			err = fmt.Errorf("%w (solver stderr: %s)", err, detail)
		}
	}
	return err
}

func (s *State) Call(ctx context.Context, operation uint32, data []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if err := ctx.Err(); err != nil {
		s.err = err
		return 0, err
	}
	switch operation {
	case 3:
		return s.write(data)
	case 4:
		return s.receive(data)
	default:
		s.err = fmt.Errorf("unknown solver callback operation %d", operation)
		return 0, s.err
	}
}

func (s *State) write(data []byte) (int, error) {
	n, err := s.session.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.err = fmt.Errorf("write to solver: %w", err)
		return 0, s.err
	}
	return 0, nil
}

func (s *State) receive(data []byte) (int, error) {
	data = data[:min(len(data), solverReadChunk)]
	n, err := s.session.Read(data)
	if n < 0 || n > len(data) {
		s.err = errors.New("solver returned an invalid byte count")
		return 0, s.err
	}
	if n > 0 {
		s.read += int64(n)
		if s.read > s.limit {
			s.err = fmt.Errorf("solver output exceeds %d bytes", s.limit)
			return 0, s.err
		}
		return n, nil
	}
	if errors.Is(err, io.EOF) {
		return 0, nil
	}
	if err == nil {
		err = io.ErrNoProgress
	}
	s.err = fmt.Errorf("read from solver: %w", err)
	return 0, s.err
}
