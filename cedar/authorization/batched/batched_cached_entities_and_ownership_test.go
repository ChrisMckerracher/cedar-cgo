package batched_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
)

func TestBatchedCachedEntitiesAndOwnership(t *testing.T) {
	f := testsupport.BatchedFixtures(t)[0]
	a := testsupport.BatchAuthorizer(t, f, authorization.Limits{MaxInstances: 1})
	req := testsupport.BatchRequest(f)
	req.Entities = cedarentity.EntitiesFromJSON(f.Batches[0].Entities)
	var retained []entityuid.EntityUID
	d, err := a.Batched().AuthorizeBatched(context.Background(), req, batched.EntityLoaderFunc(func(_ context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
		retained = uids
		return testsupport.FixtureBatch(f, 1), nil
	}), batched.BatchedOptions{MaxIterations: 2})
	if d != cedarrequest.Allow || err != nil || len(retained) != 1 || retained[0].ID != "manager" {
		t.Fatalf("cache got %s %v ids=%v", d, err, retained)
	}
	n := 0
	d, err = a.Batched().AuthorizeBatched(context.Background(), testsupport.BatchRequest(f), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
		n++
		return batched.EntityLoadResult{}, nil
	}), batched.BatchedOptions{MaxIterations: 1})
	if d != cedarrequest.Deny || err == nil || n != 1 || retained[0].ID != "manager" {
		t.Fatalf("call data leaked: %s %v n=%d retained=%v", d, err, n, retained)
	}
}

func Example_authorizeBatched() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		panic(err)
	}
	defer rt.Close(ctx)
	schema := cedarschema.SchemaFromCedar(`entity User {active: Bool}; entity Document; action "read" appliesTo {principal: User, resource: Document, context: {}};`)
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when {principal.active};`)})
	if err != nil {
		panic(err)
	}
	defer a.Close()
	loader := batched.EntityLoaderFunc(func(ctx context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
		if err := ctx.Err(); err != nil {
			return batched.EntityLoadResult{}, err
		}
		// A real loader queries its entity store for precisely these UIDs.
		data, err := json.Marshal(cedarentity.NewEntities(cedarentity.Entity{UID: uids[0], Attrs: cedarvalue.Record{"active": cedarvalue.Bool(true)}}))
		return batched.EntityLoadResult{Entities: data}, err
	})
	decision, err := a.Batched().AuthorizeBatched(ctx, cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "read"), Resource: entityuid.NewEntityUID("Document", "guide")}, loader, batched.BatchedOptions{MaxIterations: 4})
	if err != nil {
		panic(err)
	}
	fmt.Println(decision)
	// Output: allow
}

func TestBatchedLoaderCannotRedefineCachedEntities(t *testing.T) {
	schema := cedarschema.SchemaFromCedar(`entity User {enabled: Bool}; entity Resource {owner: User}; action "view" appliesTo {principal: User, resource: Resource, context: {}};`)
	cached := cedarentity.NewEntities(cedarentity.Entity{UID: entityuid.NewEntityUID("User", "alice"), Attrs: cedarvalue.Record{"enabled": cedarvalue.Bool(false)}})
	resource := `{"uid":{"type":"Resource","id":"doc"},"attrs":{"owner":{"__entity":{"type":"User","id":"alice"}}},"parents":[]}`
	for _, viaRequest := range []bool{false, true} {
		for _, mode := range []string{"different", "identical", "missing"} {
			t.Run(fmt.Sprintf("request=%t/%s", viaRequest, mode), func(t *testing.T) {
				cfg := authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when {resource.owner.enabled};`)}
				req := cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Resource", "doc")}
				if viaRequest {
					req.Entities = cached
				} else {
					cfg.Entities = cached
				}
				a, err := testsupport.TestRuntime(t).NewAuthorizer(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				calls := 0
				d, err := a.Batched().AuthorizeBatched(context.Background(), req, batched.EntityLoaderFunc(func(_ context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
					calls++
					if len(uids) != 1 || uids[0] != req.Resource {
						t.Fatalf("wanted only resource, got %v", uids)
					}
					out := batched.EntityLoadResult{Entities: json.RawMessage("[" + resource + "]")}
					if mode == "missing" {
						out.Missing = []entityuid.EntityUID{req.Principal}
					} else {
						out.Entities = json.RawMessage("[" + resource + `,{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":` + fmt.Sprint(mode == "different") + `},"parents":[]}]`)
					}
					return out, nil
				}), batched.BatchedOptions{MaxIterations: 4})
				var ce *diagnostic.Error
				if d != cedarrequest.Deny || !errors.As(err, &ce) || ce.Kind != diagnostic.KindEntities || calls != 1 {
					t.Fatalf("cache override got %s %v calls=%d", d, err, calls)
				}
			})
		}
	}
}
