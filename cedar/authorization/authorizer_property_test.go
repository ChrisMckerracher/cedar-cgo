package authorization_test

import (
	generator "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/generator"
	joy "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// The same Config+Request always yields the same decision, reasons, and errors.
func TestPropertyAuthorizeDeterministic(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: &d.Schema, Policies: d.Old, Entities: d.Entities})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		req := generator.PropGenRequest().Draw(pt, "request")
		first, err1 := a.Authorize(ctx, req)
		second, err2 := a.Authorize(ctx, req)
		if (err1 == nil) != (err2 == nil) || (err1 != nil && err1.Error() != err2.Error()) {
			pt.Fatalf("error instability: %v vs %v", err1, err2)
		}
		if !generator.PropResponseEqual(first, second) {
			pt.Fatalf("response instability: %+v vs %+v", first, second)
		}
	})
}

// Reusing one authorizer is stateless: prior requests, including per-request
// entity data, never change a fixed request's answer.
func TestPropertyAuthorizeStateless(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: &d.Schema, Policies: d.Old, Entities: d.Entities})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	baseline, err := a.Authorize(ctx, joy.JoyRequest())
	if err != nil {
		t.Fatal(err)
	}
	rapid.Check(t, func(pt *rapid.T) {
		for range rapid.IntRange(1, 3).Draw(pt, "count") {
			noisy := generator.PropGenRequest().Draw(pt, "noisy")
			if rapid.Bool().Draw(pt, "withEntities") {
				// Extras are disjoint from the preloaded store, so no UID conflicts.
				noisy.Entities = generator.PropGenExtraEntities().Draw(pt, "entities")
			}
			if _, err := a.Authorize(ctx, noisy); err != nil {
				pt.Fatalf("noisy request failed: %v", err)
			}
		}
		again, err := a.Authorize(ctx, joy.JoyRequest())
		if err != nil {
			pt.Fatalf("baseline failed: %v", err)
		}
		if !generator.PropResponseEqual(baseline, again) {
			pt.Fatalf("prior calls changed the baseline: %+v vs %+v", baseline, again)
		}
	})
}
