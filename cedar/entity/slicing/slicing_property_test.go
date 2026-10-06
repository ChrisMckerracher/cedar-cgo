package slicing_test

import (
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"
	generator "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/generator"
	joy "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	slicing "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/slicing"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Slicing preserves the decision for that request under both the full and the
// reduced entity store (slicing_test.go's documented guarantee; errors from
// policies irrelevant to the decision may differ).
func TestPropertySliceDecisionPreserved(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	joyJSON := fixture.MustReadFile(t, "../testdata/joy/entities.json")
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		TextValue := generator.PropGenPolicySet(2).Draw(pt, "policies")
		generator.PropAssertStrictlyValid(pt, rt, d.Schema, TextValue)
		entities := generator.PropGenEntityStore(joyJSON).Draw(pt, "entities").Entities
		policies := cedarpolicy.PoliciesFromCedar(TextValue)
		req := generator.PropGenRequest().Draw(pt, "request")
		slice, err := rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{Schema: d.Schema, Policies: policies, Entities: entities}, req)
		if err != nil {
			pt.Fatalf("slice: %v\n%s", err, TextValue)
		}
		for _, store := range []struct {
			name     string
			Entities cedarentity.Entities
		}{{"full", entities}, {"slice", slice.Entities}} {
			a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &d.Schema, Policies: policies, Entities: store.Entities})
			if err != nil {
				pt.Fatalf("%s store: load: %v", store.name, err)
			}
			resp, err := a.Authorize(ctx, req)
			a.Close()
			if err != nil {
				pt.Fatalf("%s store: authorize: %v", store.name, err)
			}
			if resp.Decision != slice.Decision {
				pt.Fatalf("%s store decided %v, slice decided %v\n%s", store.name, resp.Decision, slice.Decision, TextValue)
			}
		}
	})
}
