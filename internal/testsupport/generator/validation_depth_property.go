package generator

import (
	context "context"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	validation "github.com/ChrisMckerracher/cedar-cgo/cedar/validation"
	rapid "pgregory.net/rapid"
)

// Mirrored from testdata/parity/validation-depth/input.json; the Joy schema
// declares no entity attributes, so the depth-3 chain needs the fixture schema.
const (
	DepthFixtureSchema = "entity User { admin: Bool, photo: Photo }; entity Photo { owner: User }; action view appliesTo { principal: User, resource: Photo, context: {} };"
	DepthFixturePolicy = "permit(principal, action, resource) when { principal.photo.owner.admin };"
)

func ValidateWithLevelAt(t *rapid.T, rt *cedar.Runtime, schema cedarschema.Schema, policies cedarpolicy.PolicySet, level uint32) validation.ValidationResult {
	t.Helper()
	res, err := rt.Validation().ValidateWithLevel(context.Background(), schema, policies, level)
	if err != nil {
		t.Fatalf("validate with level %d: %v", level, err)
	}
	return res
}

// Hierarchy membership (`in`) is the only dereference the Joy schema can express:
// experiments and the native fixtures show record access like context.platform.os,
// `has`, and extension methods stay free, while every `in` needs level >= 1.
var DepthHierarchyConditions = []string{
	`principal in Joy::Account::"acct1"`,
	`principal is Joy::Device in Joy::Account::"acct1"`,
	`resource in Joy::Project::"proj0"`,
	`resource is Joy::Project in Joy::Machine::"m1"`,
	`action in [Joy::Action::"session.read", Joy::Action::"file.write"]`,
}

type DepthConditionCase struct {
	TextValue    string
	Dereferences bool
}

// propGenCondition never emits `in`, so generated clauses are dereference-free
// by construction and the classification is known, not sniffed from the text.
func PropGenDepthCondition() *rapid.Generator[DepthConditionCase] {
	return rapid.Custom(func(t *rapid.T) DepthConditionCase {
		if rapid.Bool().Draw(t, "hierarchy") {
			return DepthConditionCase{
				TextValue:    rapid.SampledFrom(DepthHierarchyConditions).Draw(t, "condition"),
				Dereferences: true,
			}
		}
		return DepthConditionCase{TextValue: PropGenCondition(1).Draw(t, "condition")}
	})
}
