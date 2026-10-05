package integration_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	rapid "pgregory.net/rapid"
	testing "testing"
)

// Malformed UTF-8 fails closed before instance acquisition in every request
// mode, no matter which request field carries it.
func TestPropertyMalformedUTF8RequestsFailClosed(t *testing.T) {
	ctx := context.Background()
	rt := testsupport.TestRuntime(t)
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {}};`)
	a, err := rt.NewAuthorizer(ctx, authorization.Config{
		Schema:   &schema,
		Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource);`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	rapid.Check(t, func(pt *rapid.T) {
		bad := generator.PropGenMalformed(pt, generator.PropGenUnicode.Draw(pt, "text"))
		req := cedarrequest.Request{
			Principal: entityuid.NewEntityUID("User", "u"),
			Action:    entityuid.NewEntityUID("Action", "view"),
			Resource:  entityuid.NewEntityUID("Photo", "p"),
		}
		field := rapid.SampledFrom([]string{
			"principalType", "principalID", "actionType", "actionID", "resourceType", "resourceID",
			"contextValue", "contextKey", "rawContext", "entities", "rawEntities",
		}).Draw(pt, "field")
		switch field {
		case "principalType":
			req.Principal.Type = bad
		case "principalID":
			req.Principal.ID = bad
		case "actionType":
			req.Action.Type = bad
		case "actionID":
			req.Action.ID = bad
		case "resourceType":
			req.Resource.Type = bad
		case "resourceID":
			req.Resource.ID = bad
		case "contextValue":
			req.Context = cedarrequest.NewContext(cedarvalue.Record{"a": cedarvalue.String(bad)})
		case "contextKey":
			req.Context = cedarrequest.NewContext(cedarvalue.Record{bad: cedarvalue.Bool(true)})
		case "rawContext":
			req.Context = cedarrequest.ContextFromJSON([]byte(`{"a":"` + bad + `"}`))
		case "entities":
			req.Entities = cedarentity.NewEntities(cedarentity.Entity{UID: entityuid.NewEntityUID("User", bad)})
		case "rawEntities":
			req.Entities = cedarentity.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))
		}
		partial := cedarpartial.PartialRequest{
			Principal: cedarpartial.KnownEntityUID(req.Principal),
			Action:    req.Action,
			Resource:  cedarpartial.KnownEntityUID(req.Resource),
			Context:   &req.Context,
		}
		if field == "entities" || field == "rawEntities" {
			// Mirror the malformed store into the partial leg so every field
			// exercises the same rejection path.
			partial.Entities = cedarpartial.NewPartialEntities(cedarpartial.PartialEntity{UID: entityuid.NewEntityUID("User", bad)})
		}

		resp, aerr := a.Authorize(ctx, req)
		if resp.Decision != cedarrequest.Deny {
			pt.Fatal("malformed request allowed")
		}
		generator.PropRequireUTF8InputError(pt, aerr)
		called := false
		loader := batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			called = true
			return batched.EntityLoadResult{}, nil
		})
		decision, berr := a.Batched().AuthorizeBatched(ctx, req, loader, batched.BatchedOptions{MaxIterations: 1})
		if decision != cedarrequest.Deny || called {
			pt.Fatalf("malformed batched request: %v loaderCalled=%v", decision, called)
		}
		generator.PropRequireUTF8InputError(pt, berr)
		presp, perr := a.Partial().PartialAuthorize(ctx, partial)
		if presp.Decision != cedarpartial.Undecided {
			pt.Fatal("malformed partial request decided")
		}
		generator.PropRequireUTF8InputError(pt, perr)
	})
}
