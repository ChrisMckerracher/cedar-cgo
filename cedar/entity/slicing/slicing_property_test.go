package slicing_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	slicing "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/slicing"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	rapid "pgregory.net/rapid"
	testing "testing"
)

// Slicing preserves the decision for that request under both the full and the
// reduced entity store (slicing_test.go's documented guarantee; errors from
// policies irrelevant to the decision may differ).
func TestPropertySliceDecisionPreserved(t *testing.T) {
	d := testsupport.LoadJoy(t)
	rt := testsupport.TestRuntime(t)
	joyJSON := testsupport.ReadFile(t, "../testdata/joy/entities.json")
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
