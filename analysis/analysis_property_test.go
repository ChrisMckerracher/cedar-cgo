package analysis_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	requests "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	"pgregory.net/rapid"
)

// Simple Joy-valid atoms keep SymCC encoding and solving fast.
func propAnalysisCondition(t *rapid.T) string {
	switch rapid.IntRange(0, 5).Draw(t, "atom") {
	case 0:
		return fmt.Sprintf("context.deviceLevel >= %d", rapid.IntRange(0, 3).Draw(t, "level"))
	case 1:
		return "context.machineAttested"
	case 2:
		return fmt.Sprintf("context.platform.os == %q", rapid.SampledFrom([]string{"ios", "android"}).Draw(t, "os"))
	case 3:
		return fmt.Sprintf("context.sessionId == %q", rapid.StringMatching(`x[a-z0-9]{0,3}`).Draw(t, "sid"))
	case 4:
		return fmt.Sprintf("principal == Joy::Device::%q", rapid.SampledFrom([]string{"phone1", "phone2"}).Draw(t, "device"))
	default:
		return fmt.Sprintf("resource == Joy::Session::%q", rapid.SampledFrom([]string{"s1", "s2"}).Draw(t, "session"))
	}
}

func propAnalysisPolicy(t *rapid.T, id string) string {
	effect := rapid.SampledFrom([]string{"permit", "forbid"}).Draw(t, "effect")
	principal := rapid.SampledFrom([]string{
		"principal",
		"principal is Joy::Device",
		`principal in Joy::Account::"acct1"`,
	}).Draw(t, "principal")
	action := rapid.SampledFrom([]string{
		"action",
		`action == Joy::Action::"session.write"`,
		`action in [Joy::Action::"session.read", Joy::Action::"file.read"]`,
	}).Draw(t, "action")
	resource := rapid.SampledFrom([]string{
		"resource",
		"resource is Joy::Session",
		`resource in Joy::Project::"proj1"`,
	}).Draw(t, "resource")
	clauses := rapid.SliceOfN(rapid.Custom(propAnalysisCondition), 0, 2).Draw(t, "clauses")
	conditions := ""
	if len(clauses) > 0 {
		conditions = fmt.Sprintf(" %s { %s }", rapid.SampledFrom([]string{"when", "unless"}).Draw(t, "kind"), strings.Join(clauses, " && "))
	}
	return fmt.Sprintf(`@id(%q) %s(%s, %s, %s)%s;`, id, effect, principal, action, resource, conditions)
}

// Sampled counterexamples must replay as deny→allow under concrete authorization.
// A policy set is equivalent to itself.
func TestPropertyAnalysisMatchesGroundTruth(t *testing.T) {
	a := newAnalyzer(t)
	schema := schemas.SchemaFromCedar(readFile(t, "../testdata/joy/joy.cedarschema"))
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	decide := func(policies string, req requests.Request) requests.Decision {
		az, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policy.PoliciesFromCedar(policies)})
		if err != nil {
			t.Fatalf("replay load: %v\n%s", err, policies)
		}
		defer az.Close()
		resp, err := az.Authorize(ctx, req)
		if err != nil {
			t.Fatalf("replay authorize: %v", err)
		}
		return resp.Decision
	}
	held, replayedTotal := 0, 0
	rapid.Check(t, func(pt *rapid.T) {
		replayed := 0
		count := rapid.IntRange(1, 2).Draw(pt, "count")
		parts := make([]string, 0, count+1)
		for i := range count {
			parts = append(parts, propAnalysisPolicy(pt, fmt.Sprintf("p%d", i)))
		}
		before := strings.Join(parts, "\n")
		parts = append(parts, propAnalysisPolicy(pt, "delta"))
		after := strings.Join(parts, "\n")
		report, err := a.NewlyPermitted(ctx, schema, policy.PoliciesFromCedar(before), policy.PoliciesFromCedar(after))
		if err != nil {
			pt.Fatalf("analysis: %v\nbefore:\n%s\nafter:\n%s", err, before, after)
		}
		for _, res := range report.Results {
			if res.Holds {
				held++
				continue
			}
			c := res.Counterexample
			if c == nil || c.First != requests.Deny || c.Second != requests.Allow {
				pt.Fatalf("counterexample is not newly allowed: %+v", c)
			}
			if replayed < 3 {
				replayed++
				replayedTotal++
				if got := decide(before, c.Request); got != requests.Deny {
					pt.Fatalf("counterexample %s: before decided %v, want deny\nbefore:\n%s", c.Text, got, before)
				}
				if got := decide(after, c.Request); got != requests.Allow {
					pt.Fatalf("counterexample %s: after decided %v, want allow\nafter:\n%s", c.Text, got, after)
				}
			}
		}
		if rapid.Bool().Draw(pt, "selfEquivalent") {
			report, err := a.Equivalent(ctx, schema, policy.PoliciesFromCedar(before), policy.PoliciesFromCedar(before))
			if err != nil {
				pt.Fatalf("self-equivalence: %v\n%s", err, before)
			}
			if !report.Holds() {
				pt.Fatalf("a policy set is not equivalent to itself\n%s", before)
			}
		}
	})
	t.Logf("solver-held request environments: %d, counterexamples replayed: %d", held, replayedTotal)
}
