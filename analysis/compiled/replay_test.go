package compiled_test

import (
	"context"
	"errors"
	"testing"

	compiledapi "github.com/ChrisMckerracher/cedar-cgo/analysis/compiled"
	fixtures "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/testsupport"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

func TestCompiledReuseMatchesStatelessAndReplays(t *testing.T) {
	a, solver := compiledAnalyzer(t)
	ctx := context.Background()
	schema := schemas.SchemaFromCedar(fixtures.Schema)
	x, y := fixtures.Policy("permit", "context.n < 0"), fixtures.Policy("permit", "context.n < 1")
	s, err := a.OpenCompiled(ctx, schema, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Compile(ctx, x)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Compile(ctx, y)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	for index := 0; index < 3; index++ {
		report, err := s.Equivalent(ctx, first, second)
		if err != nil {
			t.Fatal(err)
		}
		if report.Holds() {
			t.Fatal("different thresholds appeared equivalent")
		}
		for _, result := range report.Results {
			if cex := result.Counterexample; cex != nil {
				xr, yr := fixtures.Replay(t, rt, schema, x, cex.Request), fixtures.Replay(t, rt, schema, y, cex.Request)
				if xr.Decision != cex.First || yr.Decision != cex.Second || xr.Decision == yr.Decision {
					t.Fatal("compiled counterexample replay differs")
				}
			}
		}
	}
	if solver.starts.Load() != 1 {
		t.Fatal("reusable calls started additional solvers")
	}
	compiled, err := s.Equivalent(ctx, first, second)
	if err != nil {
		t.Fatal(err)
	}
	stateless, err := a.Equivalent(ctx, schema, x, y)
	if err != nil {
		t.Fatal(err)
	}
	sameCompiledResults(t, compiled, stateless)
	compiled, err = s.Implies(ctx, first, second)
	if err != nil {
		t.Fatal(err)
	}
	stateless, err = a.NewlyPermitted(ctx, schema, y, x)
	if err != nil {
		t.Fatal(err)
	}
	sameCompiledResults(t, compiled, stateless)
	compiled, err = s.Disjoint(ctx, first, second)
	if err != nil {
		t.Fatal(err)
	}
	stateless, err = a.Disjoint(ctx, schema, x, y)
	if err != nil {
		t.Fatal(err)
	}
	sameCompiledResults(t, compiled, stateless)
	if _, err := s.Compile(ctx, fixtures.Policy("permit", "context.n == true")); err == nil {
		t.Fatal("ill-typed compilation accepted")
	}
	if report, err := s.Equivalent(ctx, first, first); err != nil || !report.Holds() {
		t.Fatalf("compile error invalidated session %+v %v", report, err)
	}
	other, err := a.OpenCompiled(ctx, schema, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.Compile(ctx, x)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Equivalent(ctx, first, foreign); err == nil {
		t.Fatal("foreign handle accepted")
	}
	if err := s.Release(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Equivalent(ctx, first, second); err == nil {
		t.Fatal("released handle accepted")
	}
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if solver.starts.Load() != solver.closes.Load() {
		t.Fatal("Analyzer.Close retained solver processes")
	}
	if _, err := other.Equivalent(ctx, foreign, foreign); !errors.Is(err, compiledapi.ErrClosed) {
		t.Fatalf("closed analyzer retained session %v", err)
	}
}
