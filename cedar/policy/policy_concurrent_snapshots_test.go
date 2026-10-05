package policy_test

import (
	context "context"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
)

func TestPolicyConcurrentSnapshots(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	p, err := rt.Policies().ParsePolicy(ctx, "base", `@owner("original") permit(principal == User::"alice",action,resource);`)
	if err != nil {
		t.Fatal(err)
	}
	base, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar(""), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second", "third", "fourth"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			for range 3 {
				syntax, err := p.Syntax()
				if err != nil {
					t.Fatal(err)
				}
				syntax.ID = id
				syntax.Annotations["owner"] = id
				syntax.Principal.Entity.ID = id
				edited, err := rt.Policies().PolicyFromSyntax(ctx, syntax)
				if err != nil {
					t.Fatal(err)
				}
				set, err := rt.Policies().AddPolicy(ctx, base.Source(), edited)
				if err != nil {
					t.Fatal(err)
				}
				q, ok := set.Policy(id)
				if !ok || q.PrincipalConstraint().Entity.ID != id {
					t.Fatal("concurrent edit mixed policy state")
				}
				if len(base.Policies()) != 1 || p.PrincipalConstraint().Entity.ID != "alice" {
					t.Fatal("concurrent edit mutated original")
				}
				if owner, _ := p.Annotation("owner"); owner != "original" {
					t.Fatal("concurrent edit mutated annotations")
				}
			}
		})
	}
}
