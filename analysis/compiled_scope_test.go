package analysis_test

import (
	"context"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestCompiledEmptySelectionDoesNotEstablishPolicyValidity(t *testing.T) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(querySchema)
	policies := queryPolicy("permit", "context.n == true")
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	validation, err := rt.Validate(ctx, schema, policies)
	if err != nil || len(validation.Errors) == 0 {
		t.Fatalf("full-schema validation must reject the invalid operand type: %+v %v", validation, err)
	}
	a, _ := compiledAnalyzer(t)
	session, err := a.OpenCompiled(ctx, schema, []analysis.RequestEnvironment{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	handle, err := session.Compile(ctx, policies)
	if err != nil {
		t.Fatalf("empty selection must permit syntax inspection without type checking: %v", err)
	}
	report, err := session.Equivalent(ctx, handle, handle)
	if err != nil || len(report.Results) != 0 || !report.Holds() {
		t.Fatalf("empty selection must return an empty report: %+v %v", report, err)
	}
}
