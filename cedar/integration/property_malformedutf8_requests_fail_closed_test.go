package integration_test

import (
	partialinput "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial/input"
	generator "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/generator"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/batched"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Malformed UTF-8 fails closed before instance acquisition in every request
// mode, no matter which request field carries it.
func TestPropertyMalformedUTF8RequestsFailClosed(t *testing.T) {
	ctx := context.Background()
	rt := testruntime.New(t)
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
		partial := partialinput.PartialRequest{
			Principal: partialinput.KnownEntityUID(req.Principal),
			Action:    req.Action,
			Resource:  partialinput.KnownEntityUID(req.Resource),
			Context:   &req.Context,
		}
		if field == "entities" || field == "rawEntities" {
			// Mirror the malformed store into the partial leg so every field
			// exercises the same rejection path.
			partial.Entities = partialinput.NewPartialEntities(partialinput.PartialEntity{UID: entityuid.NewEntityUID("User", bad)})
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
