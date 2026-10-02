package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// Batched authorization with an on-demand loader agrees with the same call
// using preloaded entities and with ordinary sequential authorization.
func TestPropertyBatchedMatchesSequential(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	joyJSON := readFile(t, "../testdata/joy/entities.json")
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		text := propGenPolicySet(2).Draw(pt, "policies")
		propAssertStrictlyValid(pt, rt, d.schema, text)
		store := propGenEntityStore(joyJSON).Draw(pt, "entities")
		req := propGenRequest().Draw(pt, "request")
		a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: cedar.PoliciesFromCedar(text)})
		if err != nil {
			pt.Fatalf("load: %v\n%s", err, text)
		}
		defer a.Close()
		viaLoader, err := a.AuthorizeBatched(ctx, req, cedar.EntityLoaderFunc(func(_ context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			return store.load(pt, uids), nil
		}), cedar.BatchedOptions{MaxIterations: 8})
		if err != nil {
			pt.Fatalf("batched with loader: %v", err)
		}
		preloaded := req
		preloaded.Entities = store.entities
		viaPreload, err := a.AuthorizeBatched(ctx, preloaded, cedar.EntityLoaderFunc(func(_ context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			// Anything still requested beyond the preload is nonexistent.
			return cedar.EntityLoadResult{Missing: uids}, nil
		}), cedar.BatchedOptions{MaxIterations: 8})
		if err != nil {
			pt.Fatalf("batched with preloaded entities: %v", err)
		}
		direct, err := a.Authorize(ctx, preloaded)
		if err != nil {
			pt.Fatalf("sequential: %v", err)
		}
		if viaLoader != viaPreload || viaLoader != direct.Decision {
			pt.Fatalf("loader=%v preloaded=%v sequential=%v\n%s", viaLoader, viaPreload, direct.Decision, text)
		}
	})
}
