package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// Mirrored from testdata/parity/validation-depth/input.json; the Joy schema
// declares no entity attributes, so the depth-3 chain needs the fixture schema.
const (
	depthFixtureSchema = "entity User { admin: Bool, photo: Photo }; entity Photo { owner: User }; action view appliesTo { principal: User, resource: Photo, context: {} };"
	depthFixturePolicy = "permit(principal, action, resource) when { principal.photo.owner.admin };"
)

func validateWithLevelAt(t *rapid.T, rt *cedar.Runtime, schema cedar.Schema, policies cedar.PolicySet, level uint32) cedar.ValidationResult {
	t.Helper()
	res, err := rt.ValidateWithLevel(context.Background(), schema, policies, level)
	if err != nil {
		t.Fatalf("validate with level %d: %v", level, err)
	}
	return res
}

// Increasing the level preserves successful validation. Diagnostic comparisons
// exclude native hint choices and list order, as ordinary validation does.
func TestPropertyValidationDepthMonotonic(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	rapid.Check(t, func(pt *rapid.T) {
		policies := cedar.PoliciesFromCedar(propGenPolicySet(3).Draw(pt, "policies"))
		for n := uint32(0); n < 5; n++ {
			low := validateWithLevelAt(pt, rt, d.schema, policies, n)
			propSameValidation(pt, low, validateWithLevelAt(pt, rt, d.schema, policies, n))
			if low.Passed && !validateWithLevelAt(pt, rt, d.schema, policies, n+1).Passed {
				pt.Fatalf("passes at level %d but fails at %d\n%s", n, n+1, policies.Text())
			}
		}
	})
	// The fixture chain principal.photo.owner.admin needs exactly level 3.
	schema := cedar.SchemaFromCedar(depthFixtureSchema)
	policies := cedar.PoliciesFromCedar(depthFixturePolicy)
	ctx := context.Background()
	for level, want := range map[uint32]bool{2: false, 3: true} {
		res, err := rt.ValidateWithLevel(ctx, schema, policies, level)
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed != want {
			t.Fatalf("fixture chain at level %d: passed=%v, want %v", level, res.Passed, want)
		}
	}
}

// Hierarchy membership (`in`) is the only dereference the Joy schema can express:
// experiments and the native fixtures show record access like context.platform.os,
// `has`, and extension methods stay free, while every `in` needs level >= 1.
var depthHierarchyConditions = []string{
	`principal in Joy::Account::"acct1"`,
	`principal is Joy::Device in Joy::Account::"acct1"`,
	`resource in Joy::Project::"proj0"`,
	`resource is Joy::Project in Joy::Machine::"m1"`,
	`action in [Joy::Action::"session.read", Joy::Action::"file.write"]`,
}

type depthConditionCase struct {
	text         string
	dereferences bool
}

// propGenCondition never emits `in`, so generated clauses are dereference-free
// by construction and the classification is known, not sniffed from the text.
func propGenDepthCondition() *rapid.Generator[depthConditionCase] {
	return rapid.Custom(func(t *rapid.T) depthConditionCase {
		if rapid.Bool().Draw(t, "hierarchy") {
			return depthConditionCase{
				text:         rapid.SampledFrom(depthHierarchyConditions).Draw(t, "condition"),
				dereferences: true,
			}
		}
		return depthConditionCase{text: propGenCondition(1).Draw(t, "condition")}
	})
}

// Level zero forbids dereferences exactly: hierarchy clauses fail at 0 and pass
// at 4, while dereference-free clauses pass at both levels.
func TestPropertyValidationDepthZeroForbidsDereferences(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		cc := propGenDepthCondition().Draw(pt, "condition")
		policies := cedar.PoliciesFromCedar(
			"permit(principal, action, resource) when { " + cc.text + " };")
		high, err := rt.ValidateWithLevel(ctx, d.schema, policies, 4)
		if err != nil {
			pt.Fatalf("level 4: %v", err)
		}
		zero, err := rt.ValidateWithLevel(ctx, d.schema, policies, 0)
		if err != nil {
			pt.Fatalf("level 0: %v", err)
		}
		if !high.Passed {
			pt.Fatalf("strictly valid source failed at level 4: %v\n%s", high.Errors, policies.Text())
		}
		if high.Passed && !cc.dereferences && !zero.Passed {
			pt.Fatalf("dereference-free policy failed at level 0: %v\n%s", zero.Errors, policies.Text())
		}
		if cc.dereferences && zero.Passed {
			pt.Fatalf("hierarchy clause passed at level 0\n%s", policies.Text())
		}
	})
}
