package validation_test

import (
	generator "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/generator"
	joy "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	context "context"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Increasing the level preserves successful validation. Diagnostic comparisons
// exclude native hint choices and list order, as ordinary validation does.
func TestPropertyValidationDepthMonotonic(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	rapid.Check(t, func(pt *rapid.T) {
		policies := cedarpolicy.PoliciesFromCedar(generator.PropGenPolicySet(3).Draw(pt, "policies"))
		for n := uint32(0); n < 5; n++ {
			low := generator.ValidateWithLevelAt(pt, rt, d.Schema, policies, n)
			generator.PropSameValidation(pt, low, generator.ValidateWithLevelAt(pt, rt, d.Schema, policies, n))
			if low.Passed && !generator.ValidateWithLevelAt(pt, rt, d.Schema, policies, n+1).Passed {
				pt.Fatalf("passes at level %d but fails at %d\n%s", n, n+1, policies.Text())
			}
		}
	})
	// The fixture chain principal.photo.owner.admin needs exactly level 3.
	schema := cedarschema.SchemaFromCedar(generator.DepthFixtureSchema)
	policies := cedarpolicy.PoliciesFromCedar(generator.DepthFixturePolicy)
	ctx := context.Background()
	for level, want := range map[uint32]bool{2: false, 3: true} {
		res, err := rt.Validation().ValidateWithLevel(ctx, schema, policies, level)
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed != want {
			t.Fatalf("fixture chain at level %d: passed=%v, want %v", level, res.Passed, want)
		}
	}
}

// Level zero forbids dereferences exactly: hierarchy clauses fail at 0 and pass
// at 4, while dereference-free clauses pass at both levels.
func TestPropertyValidationDepthZeroForbidsDereferences(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		cc := generator.PropGenDepthCondition().Draw(pt, "condition")
		policies := cedarpolicy.PoliciesFromCedar(
			"permit(principal, action, resource) when { " + cc.TextValue + " };")
		high, err := rt.Validation().ValidateWithLevel(ctx, d.Schema, policies, 4)
		if err != nil {
			pt.Fatalf("level 4: %v", err)
		}
		zero, err := rt.Validation().ValidateWithLevel(ctx, d.Schema, policies, 0)
		if err != nil {
			pt.Fatalf("level 0: %v", err)
		}
		if !high.Passed {
			pt.Fatalf("strictly valid source failed at level 4: %v\n%s", high.Errors, policies.Text())
		}
		if high.Passed && !cc.Dereferences && !zero.Passed {
			pt.Fatalf("dereference-free policy failed at level 0: %v\n%s", zero.Errors, policies.Text())
		}
		if cc.Dereferences && zero.Passed {
			pt.Fatalf("hierarchy clause passed at level 0\n%s", policies.Text())
		}
	})
}
