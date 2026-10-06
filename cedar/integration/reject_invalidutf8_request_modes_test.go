package integration_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/batched"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	partialinput "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial/input"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	slicing "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/slicing"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	partialfixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/partial"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
)

func TestRejectInvalidUTF8RequestModes(t *testing.T) {
	ctx := context.Background()
	rt := testruntime.New(t)
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {}};`)
	policies := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource);`)
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	req := cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "a"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "p")}
	empty := cedarrequest.Context{}
	p := partialinput.PartialRequest{Principal: partialinput.UnknownEntityUID("User"), Action: req.Action, Resource: partialinput.UnknownEntityUID("Photo"), Context: &empty}
	continuation, err := a.Partial().PartialAuthorize(ctx, p)
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	// A closed pool proves that malformed data fails before instance acquisition.
	a.Close()
	bad := string([]byte{0xff})
	mutations := map[string]func(*cedarrequest.Request){
		"principal type": func(r *cedarrequest.Request) { r.Principal.Type = bad },
		"principal ID":   func(r *cedarrequest.Request) { r.Principal.ID = bad },
		"action type":    func(r *cedarrequest.Request) { r.Action.Type = bad },
		"action ID":      func(r *cedarrequest.Request) { r.Action.ID = bad },
		"resource type":  func(r *cedarrequest.Request) { r.Resource.Type = bad },
		"resource ID":    func(r *cedarrequest.Request) { r.Resource.ID = bad },
		"context value": func(r *cedarrequest.Request) {
			r.Context = cedarrequest.NewContext(cedarvalue.Record{"a": cedarvalue.String(bad)})
		},
		"context key": func(r *cedarrequest.Request) {
			r.Context = cedarrequest.NewContext(cedarvalue.Record{bad: cedarvalue.Bool(true)})
		},
		"raw context": func(r *cedarrequest.Request) { r.Context = cedarrequest.ContextFromJSON([]byte(`{"a":"` + bad + `"}`)) },
		"entities": func(r *cedarrequest.Request) {
			r.Entities = cedarentity.NewEntities(cedarentity.Entity{UID: entityuid.NewEntityUID("User", bad)})
		},
		"raw entities": func(r *cedarrequest.Request) {
			r.Entities = cedarentity.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))
		},
	}
	loader := batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
		t.Fatal("loader called")
		return batched.EntityLoadResult{}, nil
	})
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := req
			mutate(&r)
			resp, err := a.Authorize(ctx, r)
			if resp.Decision != cedarrequest.Deny {
				t.Fatal("malformed request allowed")
			}
			fault.RequireUTF8InputError(t, err)
			d, err := a.Batched().AuthorizeBatched(ctx, r, loader, batched.BatchedOptions{MaxIterations: 1})
			if d != cedarrequest.Deny {
				t.Fatal("malformed batched request allowed")
			}
			fault.RequireUTF8InputError(t, err)
			resp, err = continuation.Reauthorize(ctx, r)
			if resp.Decision != cedarrequest.Deny {
				t.Fatal("malformed continuation allowed")
			}
			fault.RequireUTF8InputError(t, err)
			_, err = rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{Schema: schema, Policies: policies}, r)
			fault.RequireUTF8InputError(t, err)
			partial := partialinput.PartialRequest{Principal: partialinput.KnownEntityUID(r.Principal), Action: r.Action, Resource: partialinput.KnownEntityUID(r.Resource), Context: &r.Context}
			if name == "entities" {
				partial.Entities = partialinput.NewPartialEntities(partialinput.PartialEntity{UID: entityuid.NewEntityUID("User", bad)})
			}
			if name == "raw entities" {
				partial.Entities = partialinput.PartialEntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))
			}
			presp, err := a.Partial().PartialAuthorize(ctx, partial)
			if presp.Decision != cedarpartial.Undecided {
				t.Fatal("malformed partial request decided")
			}
			fault.RequireUTF8InputError(t, err)
		})
	}
	_, err = a.Partial().PartialAuthorize(ctx, partialinput.PartialRequest{Principal: partialinput.UnknownEntityUID(bad), Action: req.Action, Resource: p.Resource})
	fault.RequireUTF8InputError(t, err)
}

func TestRejectInvalidUTF8Sources(t *testing.T) {
	ctx := context.Background()
	rt := testruntime.New(t)
	bad := string([]byte{0xff})
	goodSchema := cedarschema.SchemaFromCedar(partialfixture.PartialSchema)
	goodPolicies := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource);`)
	for _, schema := range []cedarschema.Schema{cedarschema.SchemaFromCedar(bad), cedarschema.SchemaFromJSON([]byte(`{"` + bad + `":{}}`))} {
		a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: goodPolicies})
		if a != nil {
			a.Close()
			t.Fatal("malformed schema loaded")
		}
		fault.RequireUTF8InputError(t, err)
		_, err = rt.Validation().Validate(ctx, schema, goodPolicies)
		fault.RequireUTF8InputError(t, err)
		_, err = rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{Schema: schema, Policies: goodPolicies}, cedarrequest.Request{})
		fault.RequireUTF8InputError(t, err)
	}
	for _, policies := range []cedarpolicy.PolicySet{cedarpolicy.PoliciesFromCedar("//" + bad + "\npermit(principal, action, resource);"), cedarpolicy.PoliciesFromJSON([]byte(`{"policies":{"` + bad + `":{}}}`))} {
		a, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: policies})
		if a != nil {
			a.Close()
			t.Fatal("malformed policies loaded")
		}
		fault.RequireUTF8InputError(t, err)
		_, err = rt.Validation().Validate(ctx, goodSchema, policies)
		fault.RequireUTF8InputError(t, err)
		_, err = rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{Schema: goodSchema, Policies: policies}, cedarrequest.Request{})
		fault.RequireUTF8InputError(t, err)
	}
}
