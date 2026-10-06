package policy_test

import (
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	policysupport "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/policy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
)

func TestPolicyConcurrentSnapshots(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	p, err := rt.Policies().ParsePolicy(ctx, "base", `@owner("original") permit(principal == User::"alice",action,resource);`)
	if err != nil {
		t.Fatal(err)
	}
	base, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar(""), p)
	if err != nil {
		t.Fatal(err)
	}
	principalID := func(p cedarpolicy.ParsedPolicy) any {
		return policysupport.MustPolicyJSON(t, p)["principal"].(map[string]any)["entity"].(map[string]any)["id"]
	}
	for _, id := range []string{"first", "second", "third", "fourth"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			for range 3 {
				document := policysupport.MustPolicyJSON(t, p)
				document["annotations"].(map[string]any)["owner"] = id
				document["principal"].(map[string]any)["entity"].(map[string]any)["id"] = id
				data, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				edited, err := rt.Policies().PolicyFromJSON(ctx, id, data)
				if err != nil {
					t.Fatal(err)
				}
				set, err := rt.Policies().AddPolicy(ctx, base.Source(), edited)
				if err != nil {
					t.Fatal(err)
				}
				q, ok := set.Policy(id)
				if !ok || principalID(q) != id {
					t.Fatal("concurrent edit mixed policy state")
				}
				if len(base.Policies()) != 1 || principalID(p) != "alice" {
					t.Fatal("concurrent edit mutated original")
				}
				if owner, _ := p.Annotation("owner"); owner != "original" {
					t.Fatal("concurrent edit mutated annotations")
				}
			}
		})
	}
}
