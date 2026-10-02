package analysis_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestRejectInvalidUTF8SourcesBeforeSolver(t *testing.T) {
	// A zero analyzer has no solver or module; input rejection must precede both.
	a := &analysis.Analyzer{}
	bad := string([]byte{0xff})
	for _, inputs := range []struct {
		schema        cedar.Schema
		first, second cedar.PolicySet
	}{
		{schema: cedar.SchemaFromCedar(bad)},
		{schema: cedar.SchemaFromJSON([]byte(bad))},
		{first: cedar.PoliciesFromCedar(bad)},
		{second: cedar.PoliciesFromJSON([]byte(bad))},
	} {
		_, err := a.Equivalent(context.Background(), inputs.schema, inputs.first, inputs.second)
		var e *analysis.Error
		if !errors.As(err, &e) || e.Kind != string(cedar.KindInput) {
			t.Fatalf("got %v; want input error", err)
		}
		_, err = a.NewlyPermitted(context.Background(), inputs.schema, inputs.first, inputs.second)
		if !errors.As(err, &e) || e.Kind != string(cedar.KindInput) {
			t.Fatalf("got %v; want input error", err)
		}
	}
}
