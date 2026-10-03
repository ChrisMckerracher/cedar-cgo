package analysis_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

const querySchema = `entity User; entity Document; action view appliesTo { principal: User, resource: Document, context: { n: Long } };`

func queryPolicy(effect, condition string) cedar.PolicySet {
	if condition == "" {
		return cedar.PoliciesFromCedar(effect + `(principal, action, resource);`)
	}
	return cedar.PoliciesFromCedar(fmt.Sprintf(`%s(principal, action, resource) when { %s };`, effect, condition))
}

func replayEvaluation(t testing.TB, rt *cedar.Runtime, schema cedar.Schema, policy cedar.PolicySet, request cedar.Request) cedar.Response {
	t.Helper()
	authorizer, err := rt.NewAuthorizer(context.Background(), cedar.Config{Schema: &schema, Policies: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	result, err := authorizer.Authorize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func checkPolicyReplay(t testing.TB, observation *analysis.PolicyEvaluation, response cedar.Response) {
	t.Helper()
	if observation == nil {
		return
	}
	if observation.Matched != (len(response.Reasons) > 0) || len(observation.Errors) != len(response.Errors) {
		t.Fatalf("matching/error replay differs: %+v, response %+v", observation, response)
	}
	for i, error := range observation.Errors {
		if !reflect.DeepEqual(error, response.Errors[i]) {
			t.Fatalf("error policy differs %+v %+v", observation.Errors, response.Errors)
		}
	}
}

func TestNativeErrorAndMatchingQueries(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	schema := cedar.SchemaFromCedar(querySchema)
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	type unary func(context.Context, cedar.Schema, cedar.PolicySet) (analysis.Report, error)
	type binary func(context.Context, cedar.Schema, cedar.PolicySet, cedar.PolicySet) (analysis.Report, error)
	cases := []struct {
		name  string
		one   unary
		two   binary
		x, y  cedar.PolicySet
		holds bool
	}{
		{"never-errors-safe", a.NeverErrors, nil, queryPolicy("forbid", "context.n < 0"), cedar.PolicySet{}, true},
		{"never-errors-overflow", a.NeverErrors, nil, queryPolicy("forbid", "context.n + 1 > 0"), cedar.PolicySet{}, false},
		{"always-matches-forbid", a.AlwaysMatches, nil, queryPolicy("forbid", ""), cedar.PolicySet{}, true},
		{"not-always-matches-forbid", a.AlwaysMatches, nil, queryPolicy("forbid", "context.n < 0"), cedar.PolicySet{}, false},
		{"never-matches-false", a.NeverMatches, nil, queryPolicy("forbid", "false"), cedar.PolicySet{}, true},
		{"does-match-forbid", a.NeverMatches, nil, queryPolicy("forbid", "context.n < 0"), cedar.PolicySet{}, false},
		{"same-match-different-effects", nil, a.MatchesEquivalent, queryPolicy("permit", "context.n < 0"), queryPolicy("forbid", "context.n < 0"), true},
		{"different-match-both-forbid", nil, a.MatchesEquivalent, queryPolicy("forbid", "context.n < 0"), queryPolicy("forbid", "context.n >= 0"), false},
		{"matching-implication", nil, a.MatchesImplies, queryPolicy("forbid", "context.n < 0"), queryPolicy("permit", "context.n < 1"), true},
		{"matching-implication-counterexample", nil, a.MatchesImplies, queryPolicy("forbid", "context.n < 1"), queryPolicy("permit", "context.n < 0"), false},
		{"matching-disjoint", nil, a.MatchesDisjoint, queryPolicy("forbid", "context.n < 0"), queryPolicy("forbid", "context.n >= 0"), true},
		{"matching-overlap-both-forbid", nil, a.MatchesDisjoint, queryPolicy("forbid", "context.n < 0"), queryPolicy("forbid", "context.n < 1"), false},
		{"allow-disjoint", nil, a.Disjoint, queryPolicy("permit", "context.n < 0"), queryPolicy("permit", "context.n >= 0"), true},
		{"allow-overlap", nil, a.Disjoint, queryPolicy("permit", "context.n < 0"), queryPolicy("permit", "context.n < 1"), false},
		{"forbid-sets-allow-nothing", nil, a.Disjoint, queryPolicy("forbid", ""), queryPolicy("forbid", ""), true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var report analysis.Report
			var err error
			if test.one != nil {
				report, err = test.one(ctx, schema, test.x)
			} else {
				report, err = test.two(ctx, schema, test.x, test.y)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Results) != 1 || report.Holds() != test.holds {
				t.Fatalf("report %+v, wanted holds %v", report, test.holds)
			}
			if test.holds {
				return
			}
			cex := report.Results[0].Counterexample
			if cex == nil {
				t.Fatal("no concrete counterexample")
			}
			first := replayEvaluation(t, rt, schema, test.x, cex.Request)
			second := replayEvaluation(t, rt, schema, test.y, cex.Request)
			if first.Decision != cex.First || second.Decision != cex.Second {
				t.Fatalf("decision replay differs %+v %+v %+v", first, second, cex)
			}
			checkPolicyReplay(t, cex.FirstEvaluation, first)
			checkPolicyReplay(t, cex.SecondEvaluation, second)
			if test.name == "different-match-both-forbid" && (first.Decision != cedar.Deny || second.Decision != cedar.Deny) {
				t.Fatal("forbid example must deny on both sides")
			}
			if test.name == "never-errors-overflow" && len(first.Errors) == 0 {
				t.Fatal("error query returned an ordinary nonmatch")
			}
		})
	}
}

func TestMatchingQueriesRequireOnePolicy(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	schema := cedar.SchemaFromCedar(querySchema)
	for _, source := range []string{"", `permit(principal,action,resource); forbid(principal,action,resource);`, `permit(principal == ?principal,action,resource);`} {
		if _, err := a.NeverErrors(ctx, schema, cedar.PoliciesFromCedar(source)); err == nil {
			t.Fatalf("invalid singleton accepted %s", source)
		}
	}
	_, err := a.NeverErrors(ctx, schema, queryPolicy("permit", "context.n == true"))
	var input *analysis.Error
	if !errors.As(err, &input) || input.Kind != "compile_a" {
		t.Fatalf("strict validation error %v", err)
	}
	if _, err := a.NeverMatches(ctx, cedar.SchemaFromJSON([]byte(`{}`)), cedar.PolicySet{}); err == nil {
		t.Fatal("empty schema bypassed singleton check")
	}
}

func TestSetQueriesRejectTemplatesWithoutEnvironments(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	schema := cedar.SchemaFromJSON([]byte(`{}`))
	template := cedar.PoliciesFromCedar(`permit(principal == ?principal, action, resource);`)
	static := queryPolicy("permit", "")
	for _, query := range []struct {
		name                  string
		run                   func(context.Context, cedar.Schema, cedar.PolicySet, cedar.PolicySet) (analysis.Report, error)
		firstKind, secondKind string
	}{
		{"equivalent", a.Equivalent, "compile_a", "compile_b"},
		{"newly_permitted", a.NewlyPermitted, "compile_b", "compile_a"},
		{"disjoint", a.Disjoint, "compile_a", "compile_b"},
	} {
		t.Run(query.name, func(t *testing.T) {
			for _, tc := range []struct {
				first, second cedar.PolicySet
				kind          string
			}{
				{template, static, query.firstKind},
				{static, template, query.secondKind},
			} {
				_, err := query.run(ctx, schema, tc.first, tc.second)
				var input *analysis.Error
				if !errors.As(err, &input) || input.Kind != tc.kind {
					t.Fatalf("template accepted without environments: %v; want %s", err, tc.kind)
				}
			}
			report, err := query.run(ctx, schema, static, cedar.PolicySet{})
			if err != nil || len(report.Results) != 0 || !report.Holds() {
				t.Fatalf("valid static vacuity changed: %+v %v", report, err)
			}
		})
	}
}

func TestPropertyMatchingCounterexamplesReplay(t *testing.T) {
	a, ctx := newAnalyzer(t), context.Background()
	schema := cedar.SchemaFromCedar(querySchema)
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	rapid.Check(t, func(pt *rapid.T) {
		xBoundary := rapid.IntRange(-3, 3).Draw(pt, "first_boundary")
		yBoundary := rapid.IntRange(-3, 3).Draw(pt, "second_boundary")
		x := queryPolicy(rapid.SampledFrom([]string{"permit", "forbid"}).Draw(pt, "first_effect"), fmt.Sprintf("context.n < %d", xBoundary))
		y := queryPolicy(rapid.SampledFrom([]string{"permit", "forbid"}).Draw(pt, "second_effect"), fmt.Sprintf("context.n < %d", yBoundary))
		report, err := a.MatchesEquivalent(ctx, schema, x, y)
		if err != nil {
			pt.Fatal(err)
		}
		if report.Holds() != (xBoundary == yBoundary) {
			pt.Fatalf("matching boundaries %d %d, report %+v", xBoundary, yBoundary, report)
		}
		for _, result := range report.Results {
			if result.Counterexample != nil {
				cex := result.Counterexample
				first := replayEvaluation(t, rt, schema, x, cex.Request)
				second := replayEvaluation(t, rt, schema, y, cex.Request)
				checkPolicyReplay(t, cex.FirstEvaluation, first)
				checkPolicyReplay(t, cex.SecondEvaluation, second)
				if (len(first.Reasons) > 0) == (len(second.Reasons) > 0) {
					pt.Fatal("counterexample did not distinguish native matching")
				}
			}
		}
	})
}

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
			Action        cedar.EntityUID
			ResourceType  string `json:"resource_type"`
			Holds         bool
			Confirmed     *bool                      `json:"counterexample_confirmed"`
			AEvaluation   *analysis.PolicyEvaluation `json:"a_evaluation"`
			BEvaluation   *analysis.PolicyEvaluation `json:"b_evaluation"`
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
			schema := cedar.SchemaFromCedar(test.Schema)
			x, y := cedar.PoliciesFromCedar(test.A), cedar.PoliciesFromCedar(test.B)
			if test.AFormat == "json" {
				x = cedar.PoliciesFromJSON([]byte(test.A))
			}
			if test.BFormat == "json" {
				y = cedar.PoliciesFromJSON([]byte(test.B))
			}
			var report analysis.Report
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
				var input *analysis.Error
				if test.Name != want.Name || !errors.As(err, &input) || input.Kind != want.Error.Kind || input.Message != want.Error.Message {
					t.Fatalf("native error %+v, Wasm %v", want.Error, err)
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
					t.Fatalf("native result %+v, Wasm %+v", want, result)
				}
				if (result.Counterexample == nil) != (want.Confirmed == nil) || (want.Confirmed != nil && !*want.Confirmed) {
					t.Fatal("native counterexample confirmation differs")
				}
				if result.Counterexample != nil {
					compare := func(got, expected *analysis.PolicyEvaluation) {
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
								t.Fatalf("native error %+v, Wasm %+v", error, got.Errors[i])
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
