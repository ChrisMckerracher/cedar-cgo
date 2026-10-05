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

func cloneValidationComparison(t testing.TB, result cedar.ValidationResult) cedar.ValidationResult {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var clone cedar.ValidationResult
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestValidationComparisonDiagnostics(t *testing.T) {
	schema := cedar.SchemaFromCedar(`entity String; entity User;
action a, b appliesTo {principal: User, resource: User, context: {deviceLevel: Long}};`)
	policies := cedar.PoliciesFromCedar(`permit(principal, action, resource) when { context.deviceLEvel == true };
permit(principal, action, resource) when { false };
permit(principal, action, resource) when { false };`)
	result, err := testRuntime(t).ValidateWithLevel(context.Background(), schema, policies, 4)
	if err != nil || len(result.Errors) != 2 || len(result.Warnings) != 2 || len(result.SchemaWarnings) != 1 {
		t.Fatalf("missing native diagnostics: %+v, %v", result, err)
	}
	want := propStableValidation(result)
	if want.Passed != result.Passed || !reflect.DeepEqual(want.SchemaWarnings, result.SchemaWarnings) {
		t.Fatal("comparison changed validation status or schema warnings")
	}
	// Permute captured native diagnostics to make the CI ordering failure deterministic.
	for _, change := range []struct {
		name   string
		modify func(*cedar.ValidationResult)
	}{
		{"error order", func(r *cedar.ValidationResult) { slices.Reverse(r.Errors) }},
		{"warning order", func(r *cedar.ValidationResult) { slices.Reverse(r.Warnings) }},
		{"help hint", func(r *cedar.ValidationResult) {
			r.Errors[0].Message = strings.ReplaceAll(r.Errors[0].Message, "`deviceLevel`?", "`anotherName`?")
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			next := cloneValidationComparison(t, result)
			change.modify(&next)
			if reflect.DeepEqual(result, next) {
				t.Fatal("diagnostic transformation did not change the native output")
			}
			if !reflect.DeepEqual(want, propStableValidation(next)) {
				t.Fatalf("equivalent diagnostics compare differently: %+v versus %+v", result, next)
			}
		})
	}
	for _, change := range []struct {
		name   string
		modify func(*cedar.ValidationResult)
	}{
		{"status", func(r *cedar.ValidationResult) { r.Passed = !r.Passed }},
		{"policy ID", func(r *cedar.ValidationResult) { r.Errors[0].PolicyID += "other" }},
		{"category", func(r *cedar.ValidationResult) { r.Errors[0].Category = "another_category" }},
		{"severity", func(r *cedar.ValidationResult) { r.Errors[0].Severity = cedar.SeverityWarning }},
		{"message", func(r *cedar.ValidationResult) { r.Errors[0].Message += " different detail" }},
		{"span offset", func(r *cedar.ValidationResult) { r.Errors[0].Spans[0].Offset++ }},
		{"span length", func(r *cedar.ValidationResult) { r.Errors[0].Spans[0].Length++ }},
		{"missing error", func(r *cedar.ValidationResult) { r.Errors = r.Errors[:1] }},
		{"duplicate error", func(r *cedar.ValidationResult) { r.Errors = append(r.Errors, r.Errors[0]) }},
		{"warning message", func(r *cedar.ValidationResult) { r.Warnings[0].Message += " different detail" }},
		{"duplicate warning", func(r *cedar.ValidationResult) { r.Warnings = append(r.Warnings, r.Warnings[0]) }},
		{"schema warning", func(r *cedar.ValidationResult) { r.SchemaWarnings[0].Message += " different detail" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			next := cloneValidationComparison(t, result)
			change.modify(&next)
			if reflect.DeepEqual(want, propStableValidation(next)) {
				t.Fatalf("different diagnostics compare equally: %+v versus %+v", result, next)
			}
		})
	}
}
