package analysis_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type countingSolver struct {
	base   analysis.Solver
	starts atomic.Int32
	closes atomic.Int32
}

func (s *countingSolver) Start(ctx context.Context) (analysis.Session, error) {
	transport, err := s.base.Start(ctx)
	if err != nil {
		return nil, err
	}
	s.starts.Add(1)
	return &countingTransport{Session: transport, owner: s}, nil
}

type countingTransport struct {
	analysis.Session
	owner *countingSolver
	once  sync.Once
	err   error
}

func (s *countingTransport) Close() error {
	s.once.Do(func() { s.owner.closes.Add(1); s.err = s.Session.Close() })
	return s.err
}

func compiledAnalyzer(t testing.TB, options ...analysis.Option) (*analysis.Analyzer, *countingSolver) {
	t.Helper()
	path := os.Getenv("CVC5")
	if path == "" {
		t.Skip("CVC5 is not set to the pinned solver executable")
	}
	solver := &countingSolver{base: analysis.CVC5(path)}
	a, err := analysis.New(context.Background(), solver, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	return a, solver
}

func sameCompiledResults(t testing.TB, compiled, stateless analysis.Report) {
	t.Helper()
	key := func(result analysis.Result) string {
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

func TestCompiledReuseMatchesStatelessAndReplays(t *testing.T) {
	a, solver := compiledAnalyzer(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(querySchema)
	x, y := queryPolicy("permit", "context.n < 0"), queryPolicy("permit", "context.n < 1")
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
				xr, yr := replayEvaluation(t, rt, schema, x, cex.Request), replayEvaluation(t, rt, schema, y, cex.Request)
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
	if _, err := s.Compile(ctx, queryPolicy("permit", "context.n == true")); err == nil {
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
	if _, err := other.Equivalent(ctx, foreign, foreign); !errors.Is(err, analysis.ErrCompiledClosed) {
		t.Fatalf("closed analyzer retained session %v", err)
	}
}

func TestCompiledEnvironmentSelectionAndLifetime(t *testing.T) {
	a, solver := compiledAnalyzer(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; entity Document; action view appliesTo {principal: User, resource: Document, context: {n: Long}}; action edit appliesTo {principal: User, resource: Document, context: {n: Long}};`)
	selection := []analysis.RequestEnvironment{{PrincipalType: "User", Action: cedar.NewEntityUID("Action", "view"), ResourceType: "Document"}}
	life, cancel := context.WithCancel(ctx)
	s, err := a.OpenCompiled(life, schema, selection)
	if err != nil {
		t.Fatal(err)
	}
	selection[0].PrincipalType = "changed"
	if len(s.Environments()) != 1 || s.Environments()[0].PrincipalType != "User" {
		t.Fatal("selection was not copied")
	}
	copy := s.Environments()
	copy[0].PrincipalType = "changed"
	if s.Environments()[0].PrincipalType != "User" {
		t.Fatal("environment readback changed the session")
	}
	handle, err := s.Compile(ctx, queryPolicy("permit", "context.n < 0"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := s.Equivalent(ctx, handle, handle)
	if err != nil || len(report.Results) != 1 || report.Results[0].Action.ID != "view" {
		t.Fatalf("selection report %+v %v", report, err)
	}
	valid := s.Environments()[0]
	if _, err := a.OpenCompiled(ctx, schema, []analysis.RequestEnvironment{valid, valid}); err == nil {
		t.Fatal("duplicate selection accepted")
	}
	invalid := valid
	invalid.Action = cedar.NewEntityUID("Action", "missing")
	if _, err := a.OpenCompiled(ctx, schema, []analysis.RequestEnvironment{invalid}); err == nil {
		t.Fatal("unknown selection accepted")
	}
	empty, err := a.OpenCompiled(ctx, schema, []analysis.RequestEnvironment{})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := empty.Compile(ctx, queryPolicy("permit", ""))
	if err != nil {
		t.Fatal(err)
	}
	report, err = empty.Equivalent(ctx, zero, zero)
	if err != nil || len(report.Results) != 0 || !report.Holds() {
		t.Fatalf("empty selection %+v %v", report, err)
	}
	if _, err := empty.Compile(ctx, cedar.PoliciesFromCedar(`permit(principal == ?principal,action,resource);`)); err == nil {
		t.Fatal("empty selection accepted template")
	}
	cancel()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Equivalent(ctx, handle, handle); !errors.Is(err, analysis.ErrCompiledClosed) {
		t.Fatalf("lifetime cancellation retained session %v", err)
	}
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if solver.starts.Load() != solver.closes.Load() {
		t.Fatal("failed constructors retained solvers")
	}
}

func TestCompiledSolverOutputLimitInvalidates(t *testing.T) {
	a, solver := compiledAnalyzer(t, analysis.WithMaxSolverOutput(1))
	ctx := context.Background()
	s, err := a.OpenCompiled(ctx, cedar.SchemaFromCedar(querySchema), nil)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := s.Compile(ctx, queryPolicy("permit", "context.n < 0"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Compile(ctx, queryPolicy("permit", "context.n <= -1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Equivalent(ctx, handle, second); err == nil {
		t.Fatal("solver output limit ignored")
	}
	if solver.closes.Load() != 1 {
		t.Fatal("output-limit fault kept solver alive")
	}
	if _, err := s.Equivalent(ctx, handle, handle); !errors.Is(err, analysis.ErrCompiledClosed) {
		t.Fatalf("faulted session accepted call %v", err)
	}
}

func BenchmarkRepeatedEquivalent(b *testing.B) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(querySchema)
	firstPolicies := queryPolicy("permit", "context.n < 0")
	secondPolicies := queryPolicy("permit", "context.n <= -1")
	b.Run("stateless", func(b *testing.B) {
		a, _ := compiledAnalyzer(b)
		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; index < b.N; index++ {
			report, err := a.Equivalent(ctx, schema, firstPolicies, secondPolicies)
			if err != nil || !report.Holds() {
				b.Fatalf("equivalence %+v %v", report, err)
			}
		}
	})
	b.Run("compiled", func(b *testing.B) {
		a, _ := compiledAnalyzer(b)
		s, err := a.OpenCompiled(ctx, schema, nil)
		if err != nil {
			b.Fatal(err)
		}
		first, err := s.Compile(ctx, firstPolicies)
		if err != nil {
			b.Fatal(err)
		}
		second, err := s.Compile(ctx, secondPolicies)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := s.Equivalent(ctx, first, second); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; index < b.N; index++ {
			report, err := s.Equivalent(ctx, first, second)
			if err != nil || !report.Holds() {
				b.Fatalf("equivalence %+v %v", report, err)
			}
		}
	})
}
