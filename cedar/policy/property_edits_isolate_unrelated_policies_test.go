package policy_test

import (
	generator "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/generator"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	context "context"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Adding and removing a policy restores the set exactly; unrelated policies
// keep their JSON untouched.
func TestPropertyEditsIsolateUnrelatedPolicies(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		first, err := rt.Policies().ParsePolicy(ctx, "first", generator.PropGenPolicy("first").Draw(pt, "first"))
		if err != nil {
			pt.Fatalf("parse first: %v", err)
		}
		base, err := rt.Policies().AddPolicy(ctx, cedarpolicy.ParsedPolicySet{}.Source(), first)
		if err != nil {
			pt.Fatalf("add first: %v", err)
		}
		second, err := rt.Policies().ParsePolicy(ctx, "second", generator.PropGenPolicy("second").Draw(pt, "second"))
		if err != nil {
			pt.Fatalf("parse second: %v", err)
		}
		grown, err := rt.Policies().AddPolicy(ctx, base.Source(), second)
		if err != nil {
			pt.Fatalf("add second: %v", err)
		}
		if p, ok := grown.Policy("first"); !ok {
			pt.Fatal("adding a policy dropped an unrelated policy")
		} else {
			generator.PropSameJSON(pt, p.JSON(), first.JSON())
		}
		restored, err := rt.Policies().RemovePolicy(ctx, grown.Source(), "second")
		if err != nil {
			pt.Fatalf("remove second: %v", err)
		}
		generator.PropSameJSON(pt, restored.JSON(), base.JSON())
	})
}
