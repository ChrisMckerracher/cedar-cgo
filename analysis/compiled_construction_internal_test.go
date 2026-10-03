package analysis

import (
	"context"
	"errors"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"testing"
	"time"
)

func TestCompiledAnalyzerCloseCancelsPendingConstruction(t *testing.T) {
	started := make(chan struct{})
	transport := &compiledTestTransport{closed: make(chan struct{})}
	a := &Analyzer{maxSourceBytes: 1 << 20, maxSolverOutput: 1 << 20}
	a.solver = compiledTestSolver(func(ctx context.Context) (Session, error) {
		close(started)
		<-ctx.Done()
		return transport, nil
	})
	result := make(chan error, 1)
	go func() {
		_, err := a.OpenCompiled(context.Background(), cedar.SchemaFromCedar(querySchemaForUTF8), nil)
		result <- err
	}()
	<-started
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrCompiledClosed) {
			t.Fatalf("pending constructor error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("analyzer closure did not cancel constructor")
	}
	if transport.closes.Load() != 1 {
		t.Fatal("constructor retained late solver transport")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sessions) != 0 {
		t.Fatal("failed constructor retained session registration")
	}
}

type compiledCloseErrorTransport struct {
	*compiledTestTransport
	failure error
}

func (s *compiledCloseErrorTransport) Close() error {
	_ = s.compiledTestTransport.Close()
	return s.failure
}

func TestCompiledPendingConstructionReportsCloseErrors(t *testing.T) {
	for _, throughAnalyzer := range []bool{false, true} {
		name := "constructor_cancel"
		if throughAnalyzer {
			name = "analyzer_close"
		}
		t.Run(name, func(t *testing.T) {
			failure := errors.New("late solver cleanup failed")
			transport := &compiledCloseErrorTransport{compiledTestTransport: &compiledTestTransport{closed: make(chan struct{})}, failure: failure}
			started := make(chan struct{})
			a := &Analyzer{maxSourceBytes: 1 << 20, maxSolverOutput: 1 << 20}
			a.solver = compiledTestSolver(func(ctx context.Context) (Session, error) {
				a.mu.Lock()
				var pending *CompiledSession
				for session := range a.sessions {
					pending = session
				}
				a.mu.Unlock()
				close(started)
				<-ctx.Done()
				// Return the transport after cancellation marks the registered session closed.
				<-pending.done
				return transport, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opened := make(chan error, 1)
			go func() {
				_, err := a.OpenCompiled(ctx, cedar.SchemaFromCedar(querySchemaForUTF8), nil)
				opened <- err
			}()
			<-started
			if throughAnalyzer {
				if err := a.Close(context.Background()); !errors.Is(err, failure) {
					t.Fatalf("analyzer discarded cleanup error: %v", err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-opened:
				if !errors.Is(err, failure) || !errors.Is(err, ErrCompiledClosed) {
					t.Fatalf("constructor discarded cleanup or closed error: %v", err)
				}
				if !throughAnalyzer && !errors.Is(err, context.Canceled) {
					t.Fatalf("constructor discarded cancellation: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("pending constructor did not close")
			}
			if transport.closes.Load() != 1 {
				t.Fatal("late transport did not close once")
			}
			a.mu.Lock()
			registered := len(a.sessions)
			a.mu.Unlock()
			if registered != 0 {
				t.Fatal("failed constructor retained session registration")
			}
			if !throughAnalyzer {
				if err := a.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
