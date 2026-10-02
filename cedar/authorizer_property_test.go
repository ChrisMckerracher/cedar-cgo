package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// The same Config+Request always yields the same decision, reasons, and errors.
func TestPropertyAuthorizeDeterministic(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Schema: &d.schema, Policies: d.old, Entities: d.entities})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		req := propGenRequest().Draw(pt, "request")
		first, err1 := a.Authorize(ctx, req)
		second, err2 := a.Authorize(ctx, req)
		if (err1 == nil) != (err2 == nil) || (err1 != nil && err1.Error() != err2.Error()) {
			pt.Fatalf("error instability: %v vs %v", err1, err2)
		}
		if !propResponseEqual(first, second) {
			pt.Fatalf("response instability: %+v vs %+v", first, second)
		}
	})
}

// Reusing one authorizer is stateless: prior requests, including per-request
// entity data, never change a fixed request's answer.
func TestPropertyAuthorizeStateless(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Schema: &d.schema, Policies: d.old, Entities: d.entities})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	baseline, err := a.Authorize(ctx, joyRequest())
	if err != nil {
		t.Fatal(err)
	}
	rapid.Check(t, func(pt *rapid.T) {
		for range rapid.IntRange(1, 3).Draw(pt, "count") {
			noisy := propGenRequest().Draw(pt, "noisy")
			if rapid.Bool().Draw(pt, "withEntities") {
				// Extras are disjoint from the preloaded store, so no UID conflicts.
				noisy.Entities = propGenExtraEntities().Draw(pt, "entities")
			}
			if _, err := a.Authorize(ctx, noisy); err != nil {
				pt.Fatalf("noisy request failed: %v", err)
			}
		}
		again, err := a.Authorize(ctx, joyRequest())
		if err != nil {
			pt.Fatalf("baseline failed: %v", err)
		}
		if !propResponseEqual(baseline, again) {
			pt.Fatalf("prior calls changed the baseline: %+v vs %+v", baseline, again)
		}
	})
}
