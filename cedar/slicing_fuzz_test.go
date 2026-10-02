package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzSliceEntities(f *testing.F) {
	fixture := sliceFixtures(f)[0]
	f.Add([]byte(fixture.Entities))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"uid":{"type":"User","id":"alice"},"attrs":null,"parents":[]}]`))
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, entities []byte) {
		if len(entities) > 64<<10 || nesting(string(entities)) > 40 {
			t.Skip()
		}
		cfg, req := fixture.input()
		cfg.Entities = cedar.EntitiesFromJSON(entities)
		cfg.MaxIterations = 4
		ctx, cancel := context.WithTimeout(context.Background(), fuzzLimits.CallTimeout)
		defer cancel()
		result, err := rt.SliceEntities(ctx, cfg, req)
		checkNoFault(t, err)
		if err != nil {
			if result.Decision != cedar.Deny || !result.Entities.IsZero() || len(result.Batches) != 0 {
				t.Fatalf("failed slice leaked result: %+v, %v", result, err)
			}
			return
		}
		// Independent ordinary authorization must agree with the selected data.
		for _, source := range []cedar.Entities{cfg.Entities, result.Entities} {
			checkCtx, checkCancel := context.WithTimeout(context.Background(), fuzzLimits.CallTimeout)
			a, err := rt.NewAuthorizer(checkCtx, cedar.Config{Schema: &cfg.Schema, Policies: cfg.Policies, Entities: source, Limits: fuzzLimits})
			if err != nil {
				checkCancel()
				t.Fatal(err)
			}
			response, err := a.Authorize(checkCtx, req)
			a.Close()
			checkCancel()
			if err != nil || response.Decision != result.Decision {
				t.Fatalf("authorization disagrees with slice: %+v, %v, slice=%+v", response, err, result)
			}
		}
	})
}
