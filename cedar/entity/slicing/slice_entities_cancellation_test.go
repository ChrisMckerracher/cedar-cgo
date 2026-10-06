package slicing_test

import (
	context "context"
	errors "errors"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	slicing "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/slicing"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	strings "strings"
	sync "sync"
	testing "testing"
	time "time"
)

func TestSliceEntitiesCancellation(t *testing.T) {
	rt := testruntime.New(t)
	cfg, req := SliceFixtures(t)[0].Input()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := rt.Slicing().SliceEntities(ctx, cfg, req)
	if !errors.Is(err, context.Canceled) || result.Decision != cedarrequest.Deny {
		t.Fatalf("canceled call: %+v, %v", result, err)
	}
	cfg.Policies = cedarpolicy.PoliciesFromCedar(strings.Repeat(`permit(principal, action, resource) when { principal.profile.active };`, 10000))
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result, err = rt.Slicing().SliceEntities(ctx, cfg, req)
	if !errors.Is(err, context.DeadlineExceeded) || result.Decision != cedarrequest.Deny {
		t.Fatalf("deadline: %+v, %v", result, err)
	}
	cfg, req = SliceFixtures(t)[0].Input()
	if _, err := rt.Slicing().SliceEntities(context.Background(), cfg, req); err != nil {
		t.Fatal(err)
	}
}

func TestSliceEntitiesRequestData(t *testing.T) {
	cfg, req := SliceFixtures(t)[1].Input()
	req.Entities, cfg.Entities = cfg.Entities, cedarentity.NewEntities()
	result, err := testruntime.New(t).Slicing().SliceEntities(context.Background(), cfg, req)
	if err != nil || result.Decision != cedarrequest.Allow || len(result.Batches) < 2 {
		t.Fatalf("request-specific entities: %+v, %v", result, err)
	}
}

func TestSliceEntitiesLastIteration(t *testing.T) {
	cfg, req := SliceFixtures(t)[1].Input()
	rt := testruntime.New(t)
	result, err := rt.Slicing().SliceEntities(context.Background(), cfg, req)
	if err != nil || len(result.Batches) < 2 {
		t.Fatalf("expected a relationship chain: %+v, %v", result, err)
	}
	cfg.MaxIterations = uint32(len(result.Batches))
	exact, err := rt.Slicing().SliceEntities(context.Background(), cfg, req)
	if err != nil || exact.Decision != result.Decision {
		t.Fatalf("decision on final iteration: %+v, %v", exact, err)
	}
	cfg.MaxIterations--
	limited, err := rt.Slicing().SliceEntities(context.Background(), cfg, req)
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindSlicing || limited.Decision != cedarrequest.Deny {
		t.Fatalf("insufficient iterations: %+v, %v", limited, err)
	}
}

func TestSliceEntitiesConcurrent(t *testing.T) {
	rt := testruntime.New(t)
	fixtures := SliceFixtures(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			cfg, req := fixtures[i%len(fixtures)].Input()
			result, err := rt.Slicing().SliceEntities(context.Background(), cfg, req)
			want := cedarrequest.Allow
			if fixtures[i].Name == "optional_absent" {
				want = cedarrequest.Deny
			}
			if err != nil || result.Decision != want {
				t.Errorf("concurrent request %d: %+v, %v", i, result, err)
			}
		})
	}
	wg.Wait()
}

func Example_sliceEntities() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		panic(err)
	}
	defer rt.Close(ctx)
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo { public: Bool }; action view appliesTo { principal: User, resource: Photo };`)
	policies := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { resource.public };`)
	req := cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "beach")}
	slice, err := rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{
		Schema: schema, Policies: policies,
		Entities: cedarentity.NewEntities(
			cedarentity.Entity{UID: req.Resource, Attrs: cedarvalue.Record{"public": cedarvalue.Bool(true)}},
			cedarentity.Entity{UID: entityuid.NewEntityUID("Photo", "unused"), Attrs: cedarvalue.Record{"public": cedarvalue.Bool(false)}},
		),
	}, req)
	if err != nil {
		panic(err)
	}
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policies, Entities: slice.Entities})
	if err != nil {
		panic(err)
	}
	defer a.Close()
	response, err := a.Authorize(ctx, req)
	if err != nil {
		panic(err)
	}
	fmt.Println(slice.Decision, response.Decision, len(slice.Batches))
	// Output: allow allow 1
}
