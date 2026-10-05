package analysis_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	requests "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

const querySchema = `entity User; entity Document; action view appliesTo { principal: User, resource: Document, context: { n: Long } };`

func queryPolicy(effect, condition string) policy.PolicySet {
	if condition == "" {
		return policy.PoliciesFromCedar(effect + `(principal, action, resource);`)
	}
	return policy.PoliciesFromCedar(fmt.Sprintf(`%s(principal, action, resource) when { %s };`, effect, condition))
}

func replayEvaluation(t testing.TB, rt *cedar.Runtime, schema schemas.Schema, policy policy.PolicySet, request requests.Request) requests.Response {
	t.Helper()
	authorizer, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: &schema, Policies: policy})
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

func checkPolicyReplay(t testing.TB, observation *analysis.PolicyEvaluation, response requests.Response) {
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
	schema := schemas.SchemaFromCedar(querySchema)
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	type unary func(context.Context, schemas.Schema, policy.PolicySet) (analysis.Report, error)
	type binary func(context.Context, schemas.Schema, policy.PolicySet, policy.PolicySet) (analysis.Report, error)
	cases := []struct {
		name  string
		one   unary
		two   binary
		x, y  policy.PolicySet
		holds bool
	}{
		{"never-errors-safe", a.NeverErrors, nil, queryPolicy("forbid", "context.n < 0"), policy.PolicySet{}, true},
		{"never-errors-overflow", a.NeverErrors, nil, queryPolicy("forbid", "context.n + 1 > 0"), policy.PolicySet{}, false},
		{"always-matches-forbid", a.AlwaysMatches, nil, queryPolicy("forbid", ""), policy.PolicySet{}, true},
		{"not-always-matches-forbid", a.AlwaysMatches, nil, queryPolicy("forbid", "context.n < 0"), policy.PolicySet{}, false},
		{"never-matches-false", a.NeverMatches, nil, queryPolicy("forbid", "false"), policy.PolicySet{}, true},
		{"does-match-forbid", a.NeverMatches, nil, queryPolicy("forbid", "context.n < 0"), policy.PolicySet{}, false},
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
			if test.name == "different-match-both-forbid" && (first.Decision != requests.Deny || second.Decision != requests.Deny) {
				t.Fatal("forbid example must deny on both sides")
			}
			if test.name == "never-errors-overflow" && len(first.Errors) == 0 {
				t.Fatal("error query returned an ordinary nonmatch")
			}
		})
	}
}
