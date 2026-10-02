package cedar_test

import (
	"context"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// Slicing preserves the decision for that request under both the full and the
// reduced entity store (slicing_test.go's documented guarantee; errors from
// policies irrelevant to the decision may differ).
func TestPropertySliceDecisionPreserved(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	joyJSON := readFile(t, "../testdata/joy/entities.json")
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		text := propGenPolicySet(2).Draw(pt, "policies")
		propAssertStrictlyValid(pt, rt, d.schema, text)
		entities := propGenEntityStore(joyJSON).Draw(pt, "entities").entities
		policies := cedar.PoliciesFromCedar(text)
		req := propGenRequest().Draw(pt, "request")
		slice, err := rt.SliceEntities(ctx, cedar.SliceConfig{Schema: d.schema, Policies: policies, Entities: entities}, req)
		if err != nil {
			pt.Fatalf("slice: %v\n%s", err, text)
		}
		for name, store := range map[string]cedar.Entities{"full": entities, "slice": slice.Entities} {
			a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: policies, Entities: store})
			if err != nil {
				pt.Fatalf("%s store: load: %v", name, err)
			}
			resp, err := a.Authorize(ctx, req)
			a.Close()
			if err != nil {
				pt.Fatalf("%s store: authorize: %v", name, err)
			}
			if resp.Decision != slice.Decision {
				pt.Fatalf("%s store decided %v, slice decided %v\n%s", name, resp.Decision, slice.Decision, text)
			}
		}
	})
}
