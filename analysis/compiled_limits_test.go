package analysis_test

import (
	"context"
	"errors"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"testing"
)

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
