package diagnostic_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	json "encoding/json"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
)

func TestDiagnosticMetadataIgnoresSpellingHints(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; entity Uses; action view appliesTo {principal: User, resource: User, context: {}};`)
	policies := cedarpolicy.PoliciesFromCedar(`permit(principal is Uset, action, resource);`)
	first, err := rt.Validation().Validate(ctx, schema, policies)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		next, err := rt.Validation().Validate(ctx, schema, policies)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(testsupport.StableDiagnostics(first.Errors), testsupport.StableDiagnostics(next.Errors)) {
			t.Fatalf("metadata changed: %+v %+v", first.Errors, next.Errors)
		}
	}
}

func TestDiagnosticMetadataIgnoresNativeOrder(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; action view appliesTo {principal: User, resource: User, context: {}};`)
	policies := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { 1 && 2 };`)
	first, err := rt.Validation().Validate(ctx, schema, policies)
	if err != nil || len(first.Errors) != 2 {
		t.Fatalf("missing duplicate type errors: %+v %v", first, err)
	}
	for range 10 {
		next, err := rt.Validation().Validate(ctx, schema, policies)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(generator.PropSortedMessages(first.Errors), generator.PropSortedMessages(next.Errors)) {
			t.Fatalf("metadata changed: %+v %+v", first.Errors, next.Errors)
		}
	}
}

func TestDiagnosticRawPolicyIDs(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; action view appliesTo {principal: User, resource: User, context: {}};`)
	for _, id := range []struct{ name, value string }{
		{"empty", ""},
		{"control", "quote\"\nslash\\\x00雪"},
	} {
		for _, fixtureDiagnostic := range []struct {
			name, body, category string
			severity             diagnostic.DiagnosticSeverity
		}{
			{"error", `{"Value":1}`, "unexpected_type", diagnostic.SeverityError},
			{"warning", `{"Value":false}`, "impossible_policy", diagnostic.SeverityWarning},
		} {
			t.Run(id.name+"/"+fixtureDiagnostic.name, func(t *testing.T) {
				policies := testsupport.PartialIDPolicies(t, map[string]json.RawMessage{
					id.value: testsupport.PartialIDPolicy("permit", "when", fixtureDiagnostic.body),
				})
				result, err := rt.Validation().Validate(ctx, schema, policies)
				if err != nil || result.Passed != (fixtureDiagnostic.severity == diagnostic.SeverityWarning) {
					t.Fatalf("validation: %+v %v", result, err)
				}
				messages := result.Errors
				if fixtureDiagnostic.severity == diagnostic.SeverityWarning {
					messages = result.Warnings
				}
				if len(messages) != 1 || messages[0].PolicyID != id.value || messages[0].Category != fixtureDiagnostic.category || messages[0].Severity != fixtureDiagnostic.severity || len(messages[0].Spans) != 0 {
					t.Fatalf("diagnostic %+v; want raw ID %q", messages, id.value)
				}
			})
		}
	}
}
