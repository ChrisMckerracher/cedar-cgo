package analysis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/compiled"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/internal/settings"
	fixtures "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/testsupport"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

func TestCompiledAnalyzerCloseCancelsPendingConstruction(t *testing.T) {
	started := make(chan struct{})
	transport := &fixtures.Transport{Closed: make(chan struct{})}
	a := &Analyzer{config: settings.Config{MaxSourceBytes: 1 << 20, MaxSolverOutput: 1 << 20}}
	a.solver = fixtures.Solver(func(ctx context.Context) (solver.Session, error) {
		close(started)
		<-ctx.Done()
		return transport, nil
	})
	result := make(chan error, 1)
	go func() {
		_, err := a.OpenCompiled(context.Background(), schemas.SchemaFromCedar(querySchemaForUTF8), nil)
		result <- err
	}()
	<-started
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, compiled.ErrClosed) {
			t.Fatalf("pending constructor error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("analyzer closure did not cancel constructor")
	}
	if transport.Closes.Load() != 1 {
		t.Fatal("constructor retained late solver transport")
	}
	if _, err := a.OpenCompiled(context.Background(), schemas.SchemaFromCedar(querySchemaForUTF8), nil); !errors.Is(err, compiled.ErrClosed) {
		t.Fatalf("closed analyzer accepted constructor: %v", err)
	}
}

type compiledCloseErrorTransport struct {
	*fixtures.Transport
	failure error
}

func (s *compiledCloseErrorTransport) Close() error {
	_ = s.Transport.Close()
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
			transport := &compiledCloseErrorTransport{Transport: &fixtures.Transport{Closed: make(chan struct{})}, failure: failure}
			started := make(chan struct{})
			a := &Analyzer{config: settings.Config{MaxSourceBytes: 1 << 20, MaxSolverOutput: 1 << 20}}
			a.solver = fixtures.Solver(func(ctx context.Context) (solver.Session, error) {
				close(started)
				<-ctx.Done()
				return transport, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opened := make(chan error, 1)
			go func() {
				_, err := a.OpenCompiled(ctx, schemas.SchemaFromCedar(querySchemaForUTF8), nil)
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
				if !errors.Is(err, failure) || !errors.Is(err, compiled.ErrClosed) {
					t.Fatalf("constructor discarded cleanup or closed error: %v", err)
				}
				if !throughAnalyzer && !errors.Is(err, context.Canceled) {
					t.Fatalf("constructor discarded cancellation: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("pending constructor did not close")
			}
			if transport.Closes.Load() != 1 {
				t.Fatal("late transport did not close once")
			}
			if !throughAnalyzer {
				if err := a.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

const querySchemaForUTF8 = `entity User; entity Doc; action view appliesTo {principal: User, resource: Doc, context: {}};`
