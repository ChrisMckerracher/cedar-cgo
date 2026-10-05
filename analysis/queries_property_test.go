package analysis_test

import (
	"context"
	"fmt"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	"pgregory.net/rapid"
)

func TestPropertyMatchingCounterexamplesReplay(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	schema := schemas.SchemaFromCedar(querySchema)
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	rapid.Check(t, func(pt *rapid.T) {
		xBoundary := rapid.IntRange(-3, 3).Draw(pt, "first_boundary")
		yBoundary := rapid.IntRange(-3, 3).Draw(pt, "second_boundary")
		x := queryPolicy(rapid.SampledFrom([]string{"permit", "forbid"}).Draw(pt, "first_effect"), fmt.Sprintf("context.n < %d", xBoundary))
		y := queryPolicy(rapid.SampledFrom([]string{"permit", "forbid"}).Draw(pt, "second_effect"), fmt.Sprintf("context.n < %d", yBoundary))
		report, err := a.MatchesEquivalent(ctx, schema, x, y)
		if err != nil {
			pt.Fatal(err)
		}
		if report.Holds() != (xBoundary == yBoundary) {
			pt.Fatalf("matching boundaries %d %d, report %+v", xBoundary, yBoundary, report)
		}
		for _, result := range report.Results {
			if result.Counterexample != nil {
				cex := result.Counterexample
				first := replayEvaluation(t, rt, schema, x, cex.Request)
				second := replayEvaluation(t, rt, schema, y, cex.Request)
				checkPolicyReplay(t, cex.FirstEvaluation, first)
				checkPolicyReplay(t, cex.SecondEvaluation, second)
				if (len(first.Reasons) > 0) == (len(second.Reasons) > 0) {
					pt.Fatal("counterexample did not distinguish native matching")
				}
			}
		}
	})
}
