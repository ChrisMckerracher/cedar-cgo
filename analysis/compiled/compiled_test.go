package compiled_test

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/options"
	reports "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
)

type countingSolver struct {
	base   solver.Solver
	starts atomic.Int32
	closes atomic.Int32
}

func (s *countingSolver) Start(ctx context.Context) (solver.Session, error) {
	transport, err := s.base.Start(ctx)
	if err != nil {
		return nil, err
	}
	s.starts.Add(1)
	return &countingTransport{Session: transport, owner: s}, nil
}

type countingTransport struct {
	solver.Session
	owner *countingSolver
	once  sync.Once
	err   error
}

func (s *countingTransport) Close() error {
	s.once.Do(func() { s.owner.closes.Add(1); s.err = s.Session.Close() })
	return s.err
}

func compiledAnalyzer(t testing.TB, opts ...options.Option) (*analysis.Analyzer, *countingSolver) {
	t.Helper()
	path := os.Getenv("CVC5")
	if path == "" {
		t.Skip("CVC5 is not set to the pinned solver executable")
	}
	solver := &countingSolver{base: solver.CVC5(path)}
	a, err := analysis.New(context.Background(), solver, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	return a, solver
}

func sameCompiledResults(t testing.TB, compiled, stateless reports.Report) {
	t.Helper()
	key := func(result reports.Result) string {
		return result.PrincipalType + "\x00" + result.Action.String() + "\x00" + result.ResourceType
	}
	expected := make(map[string]bool, len(stateless.Results))
	for _, result := range stateless.Results {
		expected[key(result)] = result.Holds
	}
	if len(compiled.Results) != len(expected) {
		t.Fatal("compiled environment count differs")
	}
	for _, result := range compiled.Results {
		holds, exists := expected[key(result)]
		if !exists || holds != result.Holds {
			t.Fatalf("compiled result differs %+v", result)
		}
	}
}
