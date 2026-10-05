package analysis_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func TestCompiledSolverOutputLimitInvalidates(t *testing.T) {
	a, solver := compiledAnalyzer(t, analysis.WithMaxSolverOutput(1))
	ctx := context.Background()
	s, err := a.OpenCompiled(ctx, schemas.SchemaFromCedar(querySchema), nil)
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
