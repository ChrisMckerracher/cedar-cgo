package analysis_test

import (
	"context"
	"errors"
	"testing"

	fixtures "github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/testsupport"
	reports "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func TestMatchingQueriesRequireOnePolicy(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	schema := schemas.SchemaFromCedar(fixtures.Schema)
	for _, source := range []string{"", `permit(principal,action,resource); forbid(principal,action,resource);`, `permit(principal == ?principal,action,resource);`} {
		if _, err := a.NeverErrors(ctx, schema, policy.PoliciesFromCedar(source)); err == nil {
			t.Fatalf("invalid singleton accepted %s", source)
		}
	}
	_, err := a.NeverErrors(ctx, schema, fixtures.Policy("permit", "context.n == true"))
	var input *reports.Error
	if !errors.As(err, &input) || input.Kind != "compile_a" {
		t.Fatalf("strict validation error %v", err)
	}
	if _, err := a.NeverMatches(ctx, schemas.SchemaFromJSON([]byte(`{}`)), policy.PolicySet{}); err == nil {
		t.Fatal("empty schema bypassed singleton check")
	}
}

func TestSetQueriesRejectTemplatesWithoutEnvironments(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	schema := schemas.SchemaFromJSON([]byte(`{}`))
	template := policy.PoliciesFromCedar(`permit(principal == ?principal, action, resource);`)
	static := fixtures.Policy("permit", "")
	for _, query := range []struct {
		name                  string
		run                   func(context.Context, schemas.Schema, policy.PolicySet, policy.PolicySet) (reports.Report, error)
		firstKind, secondKind string
	}{
		{"equivalent", a.Equivalent, "compile_a", "compile_b"},
		{"newly_permitted", a.NewlyPermitted, "compile_b", "compile_a"},
		{"disjoint", a.Disjoint, "compile_a", "compile_b"},
	} {
		t.Run(query.name, func(t *testing.T) {
			for _, tc := range []struct {
				first, second policy.PolicySet
				kind          string
			}{
				{template, static, query.firstKind},
				{static, template, query.secondKind},
			} {
				_, err := query.run(ctx, schema, tc.first, tc.second)
				var input *reports.Error
				if !errors.As(err, &input) || input.Kind != tc.kind {
					t.Fatalf("template accepted without environments: %v; want %s", err, tc.kind)
				}
			}
			report, err := query.run(ctx, schema, static, policy.PolicySet{})
			if err != nil || len(report.Results) != 0 || !report.Holds() {
				t.Fatalf("valid static vacuity changed: %+v %v", report, err)
			}
		})
	}
}
