package analysis

import (
	"context"
	"errors"
	"io"
	"testing"
)

type solverIO struct {
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
}

func (s solverIO) Read(data []byte) (int, error)  { return s.read(data) }
func (s solverIO) Write(data []byte) (int, error) { return s.write(data) }
func (solverIO) Close() error                     { return nil }

func TestNativeSolverCallbackIOContracts(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   uint32
		n    int
		err  error
		want error
	}{
		{"write", 3, 4, nil, nil},
		{"short write", 3, 3, nil, io.ErrShortWrite},
		{"write failure", 3, 0, io.ErrClosedPipe, io.ErrClosedPipe},
		{"read", 4, 4, nil, nil},
		{"short read", 4, 1, nil, nil},
		{"read with EOF", 4, 1, io.EOF, nil},
		{"EOF", 4, 0, io.EOF, nil},
		{"empty read", 4, 0, nil, io.ErrNoProgress},
		{"read failure", 4, 0, io.ErrClosedPipe, io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			operation := func([]byte) (int, error) { return tc.n, tc.err }
			state := sessionState{session: solverIO{operation, operation}, limit: 4}
			n, err := state.Call(context.Background(), tc.op, make([]byte, 4))
			if !errors.Is(err, tc.want) {
				t.Fatalf("callback error %v, want %v", err, tc.want)
			}
			if tc.want == nil && tc.op == 4 && n != tc.n {
				t.Fatalf("read count %d, want %d", n, tc.n)
			}
			if tc.want != nil && state.err == nil {
				t.Fatal("callback lost its transport error")
			}
		})
	}
}

func TestNativeSolverCallbackRejectsInvalidCountsAndLimits(t *testing.T) {
	for _, count := range []int{-1, 5} {
		state := sessionState{session: solverIO{read: func([]byte) (int, error) { return count, nil }}, limit: 8}
		if _, err := state.Call(context.Background(), 4, make([]byte, 4)); err == nil {
			t.Fatalf("invalid read count %d accepted", count)
		}
	}
	state := sessionState{session: solverIO{read: func([]byte) (int, error) { return 1, nil }}, limit: 1}
	if _, err := state.Call(context.Background(), 4, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Call(context.Background(), 4, make([]byte, 1)); err == nil {
		t.Fatal("solver output limit was ignored")
	}
	if _, err := state.Call(context.Background(), 3, nil); err == nil {
		t.Fatal("failed callback state was reused")
	}
}
