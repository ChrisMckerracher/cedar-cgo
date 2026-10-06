package analysis_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	reports "github.com/ChrisMckerracher/cedar-cgo/analysis/report"
	uids "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

func TestAnalysisQueriesNativeParity(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	var cases []struct {
		Name, Query, Schema, A, B string
		AFormat                   string `json:"a_format"`
		BFormat                   string `json:"b_format"`
	}
	var expected []struct {
		Name    string
		Error   *struct{ Kind, Message string }
		Results []struct {
			PrincipalType string `json:"principal_type"`
			Action        uids.EntityUID
			ResourceType  string `json:"resource_type"`
			Holds         bool
			Confirmed     *bool                     `json:"counterexample_confirmed"`
			AEvaluation   *reports.PolicyEvaluation `json:"a_evaluation"`
			BEvaluation   *reports.PolicyEvaluation `json:"b_evaluation"`
		}
	}
	if err := json.Unmarshal([]byte(readFile(t, "../testdata/parity/analysis-queries/input.json")), &cases); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(readFile(t, "../testdata/parity/analysis-queries/expected.json")), &expected); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(expected) {
		t.Fatal("native fixture count differs")
	}
	for index, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			schema := schemas.SchemaFromCedar(test.Schema)
			x, y := policy.PoliciesFromCedar(test.A), policy.PoliciesFromCedar(test.B)
			if test.AFormat == "json" {
				x = policy.PoliciesFromJSON([]byte(test.A))
			}
			if test.BFormat == "json" {
				y = policy.PoliciesFromJSON([]byte(test.B))
			}
			var report reports.Report
			var err error
			switch test.Query {
			case "never_errors":
				report, err = a.NeverErrors(ctx, schema, x)
			case "always_matches":
				report, err = a.AlwaysMatches(ctx, schema, x)
			case "never_matches":
				report, err = a.NeverMatches(ctx, schema, x)
			case "matches_equivalent":
				report, err = a.MatchesEquivalent(ctx, schema, x, y)
			case "matches_implies":
				report, err = a.MatchesImplies(ctx, schema, x, y)
			case "matches_disjoint":
				report, err = a.MatchesDisjoint(ctx, schema, x, y)
			case "disjoint":
				report, err = a.Disjoint(ctx, schema, x, y)
			case "equivalent":
				report, err = a.Equivalent(ctx, schema, x, y)
			case "implies":
				report, err = a.NewlyPermitted(ctx, schema, y, x)
			default:
				t.Fatal("unknown fixture query", test.Query)
			}
			want := expected[index]
			if want.Error != nil {
				var input *reports.Error
				if test.Name != want.Name || !errors.As(err, &input) || input.Kind != want.Error.Kind || input.Message != want.Error.Message {
					t.Fatalf("native error %+v, Go %v", want.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.Name != want.Name || len(report.Results) != len(want.Results) {
				t.Fatal("native fixture shape differs")
			}
			for index, result := range report.Results {
				want := want.Results[index]
				if result.PrincipalType != want.PrincipalType || result.Action != want.Action || result.ResourceType != want.ResourceType || result.Holds != want.Holds {
					t.Fatalf("native result %+v, Go %+v", want, result)
				}
				if (result.Counterexample == nil) != (want.Confirmed == nil) || (want.Confirmed != nil && !*want.Confirmed) {
					t.Fatal("native counterexample confirmation differs")
				}
				if result.Counterexample != nil {
					compare := func(got, expected *reports.PolicyEvaluation) {
						t.Helper()
						if got == nil || expected == nil {
							if got != expected {
								t.Fatal("native evaluation presence differs")
							}
							return
						}
						if got.Matched != expected.Matched || len(got.Errors) != len(expected.Errors) {
							t.Fatal("native evaluation differs")
						}
						for i, error := range expected.Errors {
							if !reflect.DeepEqual(got.Errors[i], error) {
								t.Fatalf("native error %+v, Go %+v", error, got.Errors[i])
							}
						}
					}
					compare(result.Counterexample.FirstEvaluation, want.AEvaluation)
					compare(result.Counterexample.SecondEvaluation, want.BEvaluation)
				}
			}
		})
	}
}
