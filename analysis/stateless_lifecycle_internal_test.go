package analysis

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/compiled"
	fixtures "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/testsupport"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

type blockedStatelessTransport struct {
	entered, closed chan struct{}
	readOnce, once  sync.Once
	closes          atomic.Int32
}

func (s *blockedStatelessTransport) Read([]byte) (int, error) {
	s.readOnce.Do(func() { close(s.entered) })
	<-s.closed
	return 0, io.EOF
}

func (s *blockedStatelessTransport) Write(data []byte) (int, error) { return len(data), nil }

func (s *blockedStatelessTransport) Close() error {
	s.once.Do(func() { s.closes.Add(1); close(s.closed) })
	return nil
}

func TestNativeAnalysisCancellationAndCloseUnblockExternalSolver(t *testing.T) {
	for _, reusable := range []bool{false, true} {
		for _, closeAnalyzer := range []bool{false, true} {
			t.Run(map[bool]string{false: "stateless", true: "compiled"}[reusable]+"/"+map[bool]string{false: "context", true: "analyzer"}[closeAnalyzer], func(t *testing.T) {
				transport := &blockedStatelessTransport{entered: make(chan struct{}), closed: make(chan struct{})}
				a, err := New(context.Background(), fixtures.Solver(func(context.Context) (solver.Session, error) { return transport, nil }))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = a.Close(context.Background()) })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				finished := make(chan error, 1)
				s := schema.SchemaFromCedar("entity User; entity Doc; action view appliesTo { principal: User, resource: Doc, context: {n: Long} };")
				p := policy.PoliciesFromCedar("permit(principal,action,resource) when {context.n < 0};")
				q := policy.PoliciesFromCedar("permit(principal,action,resource) when {context.n <= -1};")
				run := func() error { _, err := a.Equivalent(ctx, s, p, q); return err }
				var child *compiled.Session
				if reusable {
					child, err = a.OpenCompiled(context.Background(), s, nil)
					if err != nil {
						t.Fatal(err)
					}
					first, err := child.Compile(context.Background(), p)
					if err != nil {
						t.Fatal(err)
					}
					second, err := child.Compile(context.Background(), q)
					if err != nil {
						t.Fatal(err)
					}
					run = func() error { _, err := child.Equivalent(ctx, first, second); return err }
				}
				go func() { finished <- run() }()
				select {
				case <-transport.entered:
				case err := <-finished:
					t.Fatalf("native call returned before solver I/O: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("native call did not reach the external solver")
				}
				closed := make(chan error, 1)
				if closeAnalyzer {
					go func() { closed <- a.Close(context.Background()) }()
				} else {
					cancel()
				}
				select {
				case err := <-finished:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("native cancellation error %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("native cancellation kept solver I/O blocked")
				}
				if closeAnalyzer {
					select {
					case err := <-closed:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("analyzer close did not wait safely")
					}
				}
				if child != nil {
					if _, err := child.Compile(context.Background(), p); !errors.Is(err, compiled.ErrClosed) {
						t.Fatalf("closed compiled session retained native state: %v", err)
					}
				}
				if transport.closes.Load() != 1 {
					t.Fatal("native cancellation did not release solver ownership")
				}
			})
		}
	}
}
