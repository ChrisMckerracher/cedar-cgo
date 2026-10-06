package analysis_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/analysis"
	reports "github.com/ChrisMckerracher/cedar-cgo/analysis/report"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

func TestRejectInvalidUTF8SourcesBeforeSolver(t *testing.T) {
	// A zero analyzer has no solver or module; input rejection must precede both.
	a := &analysis.Analyzer{}
	bad := string([]byte{0xff})
	for _, inputs := range []struct {
		schema        schemas.Schema
		first, second policy.PolicySet
	}{
		{schema: schemas.SchemaFromCedar(bad)},
		{schema: schemas.SchemaFromJSON([]byte(bad))},
		{first: policy.PoliciesFromCedar(bad)},
		{second: policy.PoliciesFromJSON([]byte(bad))},
	} {
		_, err := a.Equivalent(context.Background(), inputs.schema, inputs.first, inputs.second)
		var e *reports.Error
		if !errors.As(err, &e) || e.Kind != string(diagnostic.KindInput) {
			t.Fatalf("got %v; want input error", err)
		}
		_, err = a.NewlyPermitted(context.Background(), inputs.schema, inputs.first, inputs.second)
		if !errors.As(err, &e) || e.Kind != string(diagnostic.KindInput) {
			t.Fatalf("got %v; want input error", err)
		}
	}
}
