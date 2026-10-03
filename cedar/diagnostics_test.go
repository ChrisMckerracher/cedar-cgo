package cedar_test

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func stableDiagnostics(values []cedar.PolicyMessage) []cedar.PolicyMessage {
	result := slices.Clone(values)
	for i := range result {
		result[i].Message = strings.Split(result[i].Message, " (help: did you mean")[0]
	}
	slices.SortFunc(result, func(a, b cedar.PolicyMessage) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return strings.Compare(string(x), string(y))
	})
	return result
}

func TestStructuredDiagnosticsNativeFixtures(t *testing.T) {
	var input []struct {
		Name, Schema, Policies string
		PoliciesJSON           json.RawMessage `json:"policies_json"`
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/diagnostics/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	// The wire uses snake_case for schema warnings.
	var native []struct {
		Name             string
		Passed           bool
		Errors, Warnings []cedar.PolicyMessage
		SchemaWarnings   []cedar.SchemaWarning `json:"schema_warnings"`
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/diagnostics/expected.json"), &native); err != nil {
		t.Fatal(err)
	}
	if len(input) != len(native) {
		t.Fatal("fixture count differs")
	}
	rt := testRuntime(t)
	ctx := context.Background()
	for i, tc := range input {
		t.Run(tc.Name, func(t *testing.T) {
			policies := cedar.PoliciesFromCedar(tc.Policies)
			if len(tc.PoliciesJSON) > 0 {
				policies = cedar.PoliciesFromJSON(tc.PoliciesJSON)
			}
			result, err := rt.Validate(ctx, cedar.SchemaFromCedar(tc.Schema), policies)
			if err != nil {
				t.Fatal(err)
			}
			want := native[i]
			if tc.Name != want.Name || result.Passed != want.Passed || !reflect.DeepEqual(stableDiagnostics(result.Errors), stableDiagnostics(want.Errors)) || !reflect.DeepEqual(stableDiagnostics(result.Warnings), stableDiagnostics(want.Warnings)) || !reflect.DeepEqual(result.SchemaWarnings, want.SchemaWarnings) {
				t.Fatalf("Go %+v; native %+v", result, want)
			}
			standalone, err := rt.SchemaWarnings(ctx, cedar.SchemaFromCedar(tc.Schema))
			if err != nil || !reflect.DeepEqual(standalone, result.SchemaWarnings) {
				t.Fatalf("standalone warnings %+v %v", standalone, err)
			}
			if tc.Name == "invalid-action-warning" {
				found := false
				for _, warning := range result.Warnings {
					if warning.Category == "invalid_action_application" && warning.Severity == cedar.SeverityWarning {
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
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; action view appliesTo {principal: User, resource: User, context: {}};`)
	for _, text := range []string{
		`permit(principal is Uset, action, resource);`,
		`permit(principal == Uset::"x", action, resource);`,
	} {
		t.Run(text, func(t *testing.T) {
			cedarResult, err := rt.Validate(ctx, schema, cedar.PoliciesFromCedar(text))
			if err != nil || len(cedarResult.Errors) != 1 || len(cedarResult.Errors[0].Spans) == 0 {
				t.Fatalf("missing Cedar type error span: %+v %v", cedarResult, err)
			}
			span := cedarResult.Errors[0].Spans[0]
			if text[span.Offset:span.Offset+span.Length] != "Uset" {
				t.Fatal("Cedar span does not select the unknown type", span)
			}
			parsed, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromCedar(text))
			if err != nil {
				t.Fatal(err)
			}
			result, err := rt.Validate(ctx, schema, parsed.Source())
			if err != nil || result.Passed || len(result.Errors) != 1 || result.Errors[0].Category != "unrecognized_entity_type" {
				t.Fatalf("missing JSON type error: %+v %v", result, err)
			}
			for _, group := range [][]cedar.PolicyMessage{result.Errors, result.Warnings} {
				for _, message := range group {
					if len(message.Spans) != 0 {
						t.Fatal("JSON diagnostic contains a temporary parser span", message)
					}
				}
			}
		})
	}
}

func TestDiagnosticMetadataIgnoresSpellingHints(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; entity Uses; action view appliesTo {principal: User, resource: User, context: {}};`)
	policies := cedar.PoliciesFromCedar(`permit(principal is Uset, action, resource);`)
	first, err := rt.Validate(ctx, schema, policies)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		next, err := rt.Validate(ctx, schema, policies)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(stableDiagnostics(first.Errors), stableDiagnostics(next.Errors)) {
			t.Fatalf("metadata changed: %+v %+v", first.Errors, next.Errors)
		}
	}
}

func TestDiagnosticMetadataIgnoresNativeOrder(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; action view appliesTo {principal: User, resource: User, context: {}};`)
	policies := cedar.PoliciesFromCedar(`permit(principal, action, resource) when { 1 && 2 };`)
	first, err := rt.Validate(ctx, schema, policies)
	if err != nil || len(first.Errors) != 2 {
		t.Fatalf("missing duplicate type errors: %+v %v", first, err)
	}
	for range 10 {
		next, err := rt.Validate(ctx, schema, policies)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(propSortedMessages(first.Errors), propSortedMessages(next.Errors)) {
			t.Fatalf("metadata changed: %+v %+v", first.Errors, next.Errors)
		}
	}
}

func TestDiagnosticRawPolicyIDs(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; action view appliesTo {principal: User, resource: User, context: {}};`)
	for _, id := range []struct{ name, value string }{
		{"empty", ""},
		{"control", "quote\"\nslash\\\x00雪"},
	} {
		for _, diagnostic := range []struct {
			name, body, category string
			severity             cedar.DiagnosticSeverity
		}{
			{"error", `{"Value":1}`, "unexpected_type", cedar.SeverityError},
			{"warning", `{"Value":false}`, "impossible_policy", cedar.SeverityWarning},
		} {
			t.Run(id.name+"/"+diagnostic.name, func(t *testing.T) {
				policies := partialIDPolicies(t, map[string]json.RawMessage{
					id.value: partialIDPolicy("permit", "when", diagnostic.body),
				})
				result, err := rt.Validate(ctx, schema, policies)
				if err != nil || result.Passed != (diagnostic.severity == cedar.SeverityWarning) {
					t.Fatalf("validation: %+v %v", result, err)
				}
				messages := result.Errors
				if diagnostic.severity == cedar.SeverityWarning {
					messages = result.Warnings
				}
				if len(messages) != 1 || messages[0].PolicyID != id.value || messages[0].Category != diagnostic.category || messages[0].Severity != diagnostic.severity || len(messages[0].Spans) != 0 {
					t.Fatalf("diagnostic %+v; want raw ID %q", messages, id.value)
				}
			})
		}
	}
}
