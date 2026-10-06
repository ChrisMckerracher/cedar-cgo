package batched_test

import (
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"
	joy "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Batched authorization with an on-demand loader agrees with the same call
// using preloaded entities and with ordinary sequential authorization.
func TestPropertyBatchedMatchesSequential(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	joyJSON := fixture.MustReadFile(t, "../testdata/joy/entities.json")
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		TextValue := generator.PropGenPolicySet(2).Draw(pt, "policies")
		generator.PropAssertStrictlyValid(pt, rt, d.Schema, TextValue)
		store := generator.PropGenEntityStore(joyJSON).Draw(pt, "entities")
		req := generator.PropGenRequest().Draw(pt, "request")
		a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &d.Schema, Policies: cedarpolicy.PoliciesFromCedar(TextValue)})
		if err != nil {
			pt.Fatalf("load: %v\n%s", err, TextValue)
		}
		defer a.Close()
		viaLoader, err := a.Batched().AuthorizeBatched(ctx, req, batched.EntityLoaderFunc(func(_ context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return store.Load(pt, uids), nil
		}), batched.BatchedOptions{MaxIterations: 8})
		if err != nil {
			pt.Fatalf("batched with loader: %v", err)
		}
		preloaded := req
		preloaded.Entities = store.Entities
		viaPreload, err := a.Batched().AuthorizeBatched(ctx, preloaded, batched.EntityLoaderFunc(func(_ context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			// Anything still requested beyond the preload is nonexistent.
			return batched.EntityLoadResult{Missing: uids}, nil
		}), batched.BatchedOptions{MaxIterations: 8})
		if err != nil {
			pt.Fatalf("batched with preloaded entities: %v", err)
		}
		direct, err := a.Authorize(ctx, preloaded)
		if err != nil {
			pt.Fatalf("sequential: %v", err)
		}
		if viaLoader != viaPreload || viaLoader != direct.Decision {
			pt.Fatalf("loader=%v preloaded=%v sequential=%v\n%s", viaLoader, viaPreload, direct.Decision, TextValue)
		}
	})
}
