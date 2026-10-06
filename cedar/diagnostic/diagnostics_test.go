package diagnostic_test

import (
	context "context"
	json "encoding/json"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	reflect "reflect"
	strings "strings"
	testing "testing"
)

func TestStructuredDiagnosticsNativeFixtures(t *testing.T) {
	var input []struct {
		Name, Schema, Policies string
		PoliciesJSON           json.RawMessage `json:"policies_json"`
	}
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/diagnostics/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	// The wire uses snake_case for schema warnings.
	var native []struct {
		Name             string
		Passed           bool
		Errors, Warnings []diagnostic.PolicyMessage
		SchemaWarnings   []diagnostic.SchemaWarning `json:"schema_warnings"`
	}
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/diagnostics/expected.json"), &native); err != nil {
		t.Fatal(err)
	}
	if len(input) != len(native) {
		t.Fatal("fixture count differs")
	}
	rt := testruntime.New(t)
	ctx := context.Background()
	for i, tc := range input {
		t.Run(tc.Name, func(t *testing.T) {
			policies := cedarpolicy.PoliciesFromCedar(tc.Policies)
			if len(tc.PoliciesJSON) > 0 {
				policies = cedarpolicy.PoliciesFromJSON(tc.PoliciesJSON)
			}
			result, err := rt.Validation().Validate(ctx, cedarschema.SchemaFromCedar(tc.Schema), policies)
			if err != nil {
				t.Fatal(err)
			}
			want := native[i]
			if tc.Name != want.Name || result.Passed != want.Passed || !reflect.DeepEqual(StableDiagnostics(result.Errors), StableDiagnostics(want.Errors)) || !reflect.DeepEqual(StableDiagnostics(result.Warnings), StableDiagnostics(want.Warnings)) || !reflect.DeepEqual(result.SchemaWarnings, want.SchemaWarnings) {
				t.Fatalf("Go %+v; native %+v", result, want)
			}
			standalone, err := rt.Schemas().SchemaWarnings(ctx, cedarschema.SchemaFromCedar(tc.Schema))
			if err != nil || !reflect.DeepEqual(standalone, result.SchemaWarnings) {
				t.Fatalf("standalone warnings %+v %v", standalone, err)
			}
			if tc.Name == "invalid-action-warning" {
				found := false
				for _, warning := range result.Warnings {
					if warning.Category == "invalid_action_application" && warning.Severity == diagnostic.SeverityWarning {
						found = true
					}
				}
				if !result.Passed || len(result.Errors) != 0 || !found {
					t.Fatal("Cedar 4.13 warning severity changed", result)
				}
			}
			if tc.Name == "type-error-unicode" {
				if len(result.Errors) != 1 || len(result.Errors[0].Spans) == 0 {
					t.Fatal("missing type error span", result)
				}
				span := result.Errors[0].Spans[0]
				if !strings.Contains(tc.Policies[span.Offset:span.Offset+span.Length], "1") {
					t.Fatal("span does not select invalid operand", span)
				}
			}
		})
	}
}

func TestDiagnosticJSONPolicySpans(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; action view appliesTo {principal: User, resource: User, context: {}};`)
	for _, TextValue := range []string{
		`permit(principal is Uset, action, resource);`,
		`permit(principal == Uset::"x", action, resource);`,
	} {
		t.Run(TextValue, func(t *testing.T) {
			cedarResult, err := rt.Validation().Validate(ctx, schema, cedarpolicy.PoliciesFromCedar(TextValue))
			if err != nil || len(cedarResult.Errors) != 1 || len(cedarResult.Errors[0].Spans) == 0 {
				t.Fatalf("missing Cedar type error span: %+v %v", cedarResult, err)
			}
			span := cedarResult.Errors[0].Spans[0]
			if TextValue[span.Offset:span.Offset+span.Length] != "Uset" {
				t.Fatal("Cedar span does not select the unknown type", span)
			}
			parsed, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromCedar(TextValue))
			if err != nil {
				t.Fatal(err)
			}
			result, err := rt.Validation().Validate(ctx, schema, parsed.Source())
			if err != nil || result.Passed || len(result.Errors) != 1 || result.Errors[0].Category != "unrecognized_entity_type" {
				t.Fatalf("missing JSON type error: %+v %v", result, err)
			}
			for _, group := range [][]diagnostic.PolicyMessage{result.Errors, result.Warnings} {
				for _, message := range group {
					if len(message.Spans) != 0 {
						t.Fatal("JSON diagnostic contains a temporary parser span", message)
					}
				}
			}
		})
	}
}
