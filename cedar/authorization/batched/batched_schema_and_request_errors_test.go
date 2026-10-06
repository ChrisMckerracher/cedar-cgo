package batched_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func TestBatchedSchemaAndRequestErrors(t *testing.T) {
	f := BatchedFixtures(t)[0]
	for _, mode := range []string{"no_schema", "bad_request", "bad_context", "nil_loader"} {
		t.Run(mode, func(t *testing.T) {
			schema := cedarschema.SchemaFromCedar(f.Schema)
			cfg := authorization.Config{Policies: cedarpolicy.PoliciesFromCedar(f.Policies), Schema: &schema}
			if mode == "no_schema" {
				cfg.Schema = nil
			}
			a, err := testruntime.New(t).NewAuthorizer(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			req := BatchRequest(f)
			want := diagnostic.KindSchema
			switch mode {
			case "bad_request":
				req.Principal = entityuid.NewEntityUID("Resource", "wrong")
				want = diagnostic.KindRequest
			case "bad_context":
				req.Context = cedarrequest.ContextFromJSON([]byte(`{"unknown":true}`))
				want = diagnostic.KindContext
			case "nil_loader":
				want = diagnostic.KindInput
			}
			var loader batched.EntityLoader = batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
				t.Error("invalid call reached callback")
				return batched.EntityLoadResult{}, nil
			})
			if mode == "nil_loader" {
				loader = nil
			}
			d, err := a.Batched().AuthorizeBatched(context.Background(), req, loader, batched.BatchedOptions{MaxIterations: 2})
			var ce *diagnostic.Error
			if d != cedarrequest.Deny || !errors.As(err, &ce) || ce.Kind != want {
				t.Fatalf("got %s %v want %s", d, err, want)
			}
		})
	}
}
