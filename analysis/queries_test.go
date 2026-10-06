package analysis_test

import (
	"context"
	"reflect"
	"testing"

	fixtures "github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/testsupport"
	reports "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	requests "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func checkPolicyReplay(t testing.TB, observation *reports.PolicyEvaluation, response requests.Response) {
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
	schema := schemas.SchemaFromCedar(fixtures.Schema)
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	type unary func(context.Context, schemas.Schema, policy.PolicySet) (reports.Report, error)
	type binary func(context.Context, schemas.Schema, policy.PolicySet, policy.PolicySet) (reports.Report, error)
	cases := []struct {
		name  string
		one   unary
		two   binary
		x, y  policy.PolicySet
		holds bool
	}{
		{"never-errors-safe", a.NeverErrors, nil, fixtures.Policy("forbid", "context.n < 0"), policy.PolicySet{}, true},
		{"never-errors-overflow", a.NeverErrors, nil, fixtures.Policy("forbid", "context.n + 1 > 0"), policy.PolicySet{}, false},
		{"always-matches-forbid", a.AlwaysMatches, nil, fixtures.Policy("forbid", ""), policy.PolicySet{}, true},
		{"not-always-matches-forbid", a.AlwaysMatches, nil, fixtures.Policy("forbid", "context.n < 0"), policy.PolicySet{}, false},
		{"never-matches-false", a.NeverMatches, nil, fixtures.Policy("forbid", "false"), policy.PolicySet{}, true},
		{"does-match-forbid", a.NeverMatches, nil, fixtures.Policy("forbid", "context.n < 0"), policy.PolicySet{}, false},
		{"same-match-different-effects", nil, a.MatchesEquivalent, fixtures.Policy("permit", "context.n < 0"), fixtures.Policy("forbid", "context.n < 0"), true},
		{"different-match-both-forbid", nil, a.MatchesEquivalent, fixtures.Policy("forbid", "context.n < 0"), fixtures.Policy("forbid", "context.n >= 0"), false},
		{"matching-implication", nil, a.MatchesImplies, fixtures.Policy("forbid", "context.n < 0"), fixtures.Policy("permit", "context.n < 1"), true},
		{"matching-implication-counterexample", nil, a.MatchesImplies, fixtures.Policy("forbid", "context.n < 1"), fixtures.Policy("permit", "context.n < 0"), false},
		{"matching-disjoint", nil, a.MatchesDisjoint, fixtures.Policy("forbid", "context.n < 0"), fixtures.Policy("forbid", "context.n >= 0"), true},
		{"matching-overlap-both-forbid", nil, a.MatchesDisjoint, fixtures.Policy("forbid", "context.n < 0"), fixtures.Policy("forbid", "context.n < 1"), false},
		{"allow-disjoint", nil, a.Disjoint, fixtures.Policy("permit", "context.n < 0"), fixtures.Policy("permit", "context.n >= 0"), true},
		{"allow-overlap", nil, a.Disjoint, fixtures.Policy("permit", "context.n < 0"), fixtures.Policy("permit", "context.n < 1"), false},
		{"forbid-sets-allow-nothing", nil, a.Disjoint, fixtures.Policy("forbid", ""), fixtures.Policy("forbid", ""), true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var report reports.Report
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
			first := fixtures.Replay(t, rt, schema, test.x, cex.Request)
			second := fixtures.Replay(t, rt, schema, test.y, cex.Request)
			if first.Decision != cex.First || second.Decision != cex.Second {
				t.Fatalf("decision replay differs %+v %+v %+v", first, second, cex)
			}
			checkPolicyReplay(t, cex.FirstEvaluation, first)
			checkPolicyReplay(t, cex.SecondEvaluation, second)
			if test.name == "different-match-both-forbid" && (first.Decision != requests.Deny || second.Decision != requests.Deny) {
				t.Fatal("forbid example must deny on both sides")
			}
			if test.name == "never-errors-overflow" && len(first.Errors) == 0 {
				t.Fatal("error query returned an ordinary nonmatch")
			}
		})
	}
}
