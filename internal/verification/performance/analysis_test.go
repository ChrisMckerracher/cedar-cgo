package performance

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/analysis"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

type solverCounts struct {
	started, closed, reads, writes atomic.Uint64
	base                           solver.Solver
}

func (s *solverCounts) Start(ctx context.Context) (solver.Session, error) {
	transport, err := s.base.Start(ctx)
	if err != nil {
		return nil, err
	}
	s.started.Add(1)
	return &countedSolver{Session: transport, owner: s}, nil
}

type countedSolver struct {
	solver.Session
	owner *solverCounts
	once  sync.Once
	err   error
}

func (s *countedSolver) Read(data []byte) (int, error) {
	s.owner.reads.Add(1)
	return s.Session.Read(data)
}

func (s *countedSolver) Write(data []byte) (int, error) {
	s.owner.writes.Add(1)
	return s.Session.Write(data)
}

func (s *countedSolver) Close() error {
	s.once.Do(func() { s.owner.closed.Add(1); s.err = s.Session.Close() })
	return s.err
}

func analysisInputs() (schema.Schema, policy.PolicySet, policy.PolicySet) {
	return schema.SchemaFromCedar("entity User; entity Doc; action view appliesTo {principal: User, resource: Doc, context: {n: Long}};"), policy.PoliciesFromCedar("permit(principal,action,resource) when {context.n < 0};"), policy.PoliciesFromCedar("permit(principal,action,resource) when {context.n <= -1};")
}

func measuredAnalyzer(t testing.TB) (*analysis.Analyzer, *solverCounts) {
	t.Helper()
	path := os.Getenv("CVC5")
	if path == "" {
		t.Skip("CVC5 is required for controlled solver measurements")
	}
	counts := &solverCounts{base: solver.CVC5(path)}
	analyzer, err := analysis.New(context.Background(), counts)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer, counts
}

func BenchmarkControlledSolver(b *testing.B) {
	analyzer, counts := measuredAnalyzer(b)
	defer analyzer.Close(context.Background())
	source, first, second := analysisInputs()
	b.ReportAllocs()
	for b.Loop() {
		report, err := analyzer.Equivalent(context.Background(), source, first, second)
		if err != nil || !report.Holds() {
			b.Fatal(report, err)
		}
	}
	reportSolverCounts(b, counts)
}

func BenchmarkControlledCompiled(b *testing.B) {
	analyzer, counts := measuredAnalyzer(b)
	defer analyzer.Close(context.Background())
	source, first, second := analysisInputs()
	session, err := analyzer.OpenCompiled(context.Background(), source, nil)
	if err != nil {
		b.Fatal(err)
	}
	handleA, err := session.Compile(context.Background(), first)
	if err != nil {
		b.Fatal(err)
	}
	handleB, err := session.Compile(context.Background(), second)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := session.Equivalent(context.Background(), handleA, handleB); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		report, err := session.Equivalent(context.Background(), handleA, handleB)
		if err != nil || !report.Holds() {
			b.Fatal(report, err)
		}
	}
	if err := session.Close(); err != nil {
		b.Fatal(err)
	}
	reportSolverCounts(b, counts)
}

func reportSolverCounts(b *testing.B, counts *solverCounts) {
	b.ReportMetric(float64(counts.started.Load()), "solver-starts")
	b.ReportMetric(float64(counts.closed.Load()), "solver-closes")
	b.ReportMetric(float64(counts.reads.Load()), "solver-reads")
	b.ReportMetric(float64(counts.writes.Load()), "solver-writes")
}
