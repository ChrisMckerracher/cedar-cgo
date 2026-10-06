package compiled_test

import (
	"context"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/compiled"
	fixtures "github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/testsupport"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func TestCompiledEmptySelectionDoesNotEstablishPolicyValidity(t *testing.T) {
	ctx := context.Background()
	schema := schemas.SchemaFromCedar(fixtures.Schema)
	policies := fixtures.Policy("permit", "context.n == true")
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	validation, err := rt.Validation().Validate(ctx, schema, policies)
	if err != nil || len(validation.Errors) == 0 {
		t.Fatalf("full-schema validation must reject the invalid operand type: %+v %v", validation, err)
	}
	a, _ := compiledAnalyzer(t)
	session, err := a.OpenCompiled(ctx, schema, []compiled.RequestEnvironment{})
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
