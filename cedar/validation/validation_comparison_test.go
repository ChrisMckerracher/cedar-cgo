package validation_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	context "context"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	validation "github.com/ChrisMckerracher/cedar-go-wasm/cedar/validation"

	reflect "reflect"
	slices "slices"
	strings "strings"
	testing "testing"
)

func TestValidationComparisonDiagnostics(t *testing.T) {
	schema := cedarschema.SchemaFromCedar(`entity String; entity User;
action a, b appliesTo {principal: User, resource: User, context: {deviceLevel: Long}};`)
	policies := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { context.deviceLEvel == true };
permit(principal, action, resource) when { false };
permit(principal, action, resource) when { false };`)
	result, err := testruntime.New(t).Validation().ValidateWithLevel(context.Background(), schema, policies, 4)
	if err != nil || len(result.Errors) != 2 || len(result.Warnings) != 2 || len(result.SchemaWarnings) != 1 {
		t.Fatalf("missing native diagnostics: %+v, %v", result, err)
	}
	want := generator.PropStableValidation(result)
	if want.Passed != result.Passed || !reflect.DeepEqual(want.SchemaWarnings, result.SchemaWarnings) {
		t.Fatal("comparison changed validation status or schema warnings")
	}
	// Permute captured native diagnostics to make the CI ordering failure deterministic.
	for _, change := range []struct {
		name   string
		modify func(*validation.ValidationResult)
	}{
		{"error order", func(r *validation.ValidationResult) { slices.Reverse(r.Errors) }},
		{"warning order", func(r *validation.ValidationResult) { slices.Reverse(r.Warnings) }},
		{"help hint", func(r *validation.ValidationResult) {
			r.Errors[0].Message = strings.ReplaceAll(r.Errors[0].Message, "`deviceLevel`?", "`anotherName`?")
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			next := CloneValidationComparison(t, result)
			change.modify(&next)
			if reflect.DeepEqual(result, next) {
				t.Fatal("diagnostic transformation did not change the native output")
			}
			if !reflect.DeepEqual(want, generator.PropStableValidation(next)) {
				t.Fatalf("equivalent diagnostics compare differently: %+v versus %+v", result, next)
			}
		})
	}
	for _, change := range []struct {
		name   string
		modify func(*validation.ValidationResult)
	}{
		{"status", func(r *validation.ValidationResult) { r.Passed = !r.Passed }},
		{"policy ID", func(r *validation.ValidationResult) { r.Errors[0].PolicyID += "other" }},
		{"category", func(r *validation.ValidationResult) { r.Errors[0].Category = "another_category" }},
		{"severity", func(r *validation.ValidationResult) { r.Errors[0].Severity = diagnostic.SeverityWarning }},
		{"message", func(r *validation.ValidationResult) { r.Errors[0].Message += " different detail" }},
		{"span offset", func(r *validation.ValidationResult) { r.Errors[0].Spans[0].Offset++ }},
		{"span length", func(r *validation.ValidationResult) { r.Errors[0].Spans[0].Length++ }},
		{"missing error", func(r *validation.ValidationResult) { r.Errors = r.Errors[:1] }},
		{"duplicate error", func(r *validation.ValidationResult) { r.Errors = append(r.Errors, r.Errors[0]) }},
		{"warning message", func(r *validation.ValidationResult) { r.Warnings[0].Message += " different detail" }},
		{"duplicate warning", func(r *validation.ValidationResult) { r.Warnings = append(r.Warnings, r.Warnings[0]) }},
		{"schema warning", func(r *validation.ValidationResult) { r.SchemaWarnings[0].Message += " different detail" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			next := CloneValidationComparison(t, result)
			change.modify(&next)
			if reflect.DeepEqual(want, generator.PropStableValidation(next)) {
				t.Fatalf("different diagnostics compare equally: %+v versus %+v", result, next)
			}
		})
	}
}
