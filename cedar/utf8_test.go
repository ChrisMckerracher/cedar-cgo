package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestAuthorizeRejectsInvalidUTF8Identity(t *testing.T) {
	a, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{
		Policies: cedar.PoliciesFromCedar(`permit(principal == User::"\u{fffd}", action, resource);`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", string([]byte{0xff})),
		Action:    cedar.NewEntityUID("Action", "view"),
		Resource:  cedar.NewEntityUID("Resource", "item"),
	}
	resp, err := a.Authorize(context.Background(), req)
	var ce *cedar.Error
	if resp.Decision != cedar.Deny || !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
		t.Fatalf("malformed identity: decision=%s error=%v; want deny and KindInput", resp.Decision, err)
	}
	req.Principal.ID = "\ufffd"
	resp, err = a.Authorize(context.Background(), req)
	if err != nil || resp.Decision != cedar.Allow {
		t.Fatalf("valid replacement character: decision=%s error=%v; want allow", resp.Decision, err)
	}
}

func requireUTF8InputError(t testing.TB, err error) {
	t.Helper()
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
		t.Fatalf("got %v; want KindInput", err)
	}
}

func TestRejectInvalidUTF8Values(t *testing.T) {
	bad := string([]byte{0xff})
	uid := cedar.NewEntityUID("User", bad)
	record := cedar.Record{bad: cedar.Bool(true)}
	cases := map[string]any{
		"UID type": cedar.NewEntityUID(bad, "a"), "UID ID": uid,
		"string": cedar.String(bad), "decimal": cedar.Decimal(bad),
		"IP": cedar.IPAddr(bad), "datetime": cedar.Datetime(bad), "duration": cedar.Duration(bad),
		"record key": record, "nested set": cedar.Set{cedar.Record{"a": cedar.Set{cedar.String(bad)}}},
		"entity UID":       cedar.Entity{UID: uid},
		"entity parent":    cedar.Entity{UID: cedar.NewEntityUID("User", "a"), Parents: []cedar.EntityUID{uid}},
		"entity attribute": cedar.Entity{Attrs: cedar.Record{"a": cedar.String(bad)}},
		"entity tag":       cedar.Entity{Tags: record},
		"raw entities":     cedar.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`)),
		"raw context":      cedar.ContextFromJSON([]byte(`{"a":"` + bad + `"}`)),
		"partial UID type": cedar.UnknownEntityUID(bad), "partial UID ID": cedar.KnownEntityUID(uid),
		"partial entity UID":        cedar.PartialEntity{UID: uid},
		"partial entity parent":     cedar.PartialEntity{Parents: []cedar.EntityUID{uid}},
		"partial entity attributes": cedar.PartialEntity{Attrs: &record},
		"partial entity tags":       cedar.PartialEntity{Tags: &record},
		"raw partial entities":      cedar.PartialEntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`)),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := json.Marshal(value)
			if err == nil {
				t.Fatal("malformed UTF-8 encoded without an error")
			}
		})
	}
}

func TestRejectInvalidUTF8RequestModes(t *testing.T) {
	ctx := context.Background()
	rt := testRuntime(t)
	schema := cedar.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {}};`)
	policies := cedar.PoliciesFromCedar(`permit(principal, action, resource);`)
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	req := cedar.Request{Principal: cedar.NewEntityUID("User", "a"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "p")}
	empty := cedar.Context{}
	p := cedar.PartialRequest{Principal: cedar.UnknownEntityUID("User"), Action: req.Action, Resource: cedar.UnknownEntityUID("Photo"), Context: &empty}
	continuation, err := a.PartialAuthorize(ctx, p)
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	// A closed pool proves that malformed data fails before instance acquisition.
	a.Close()
	bad := string([]byte{0xff})
	mutations := map[string]func(*cedar.Request){
		"principal type": func(r *cedar.Request) { r.Principal.Type = bad },
		"principal ID":   func(r *cedar.Request) { r.Principal.ID = bad },
		"action type":    func(r *cedar.Request) { r.Action.Type = bad },
		"action ID":      func(r *cedar.Request) { r.Action.ID = bad },
		"resource type":  func(r *cedar.Request) { r.Resource.Type = bad },
		"resource ID":    func(r *cedar.Request) { r.Resource.ID = bad },
		"context value":  func(r *cedar.Request) { r.Context = cedar.NewContext(cedar.Record{"a": cedar.String(bad)}) },
		"context key":    func(r *cedar.Request) { r.Context = cedar.NewContext(cedar.Record{bad: cedar.Bool(true)}) },
		"raw context":    func(r *cedar.Request) { r.Context = cedar.ContextFromJSON([]byte(`{"a":"` + bad + `"}`)) },
		"entities": func(r *cedar.Request) {
			r.Entities = cedar.NewEntities(cedar.Entity{UID: cedar.NewEntityUID("User", bad)})
		},
		"raw entities": func(r *cedar.Request) {
			r.Entities = cedar.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))
		},
	}
	loader := cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
		t.Fatal("loader called")
		return cedar.EntityLoadResult{}, nil
	})
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := req
			mutate(&r)
			resp, err := a.Authorize(ctx, r)
			if resp.Decision != cedar.Deny {
				t.Fatal("malformed request allowed")
			}
			requireUTF8InputError(t, err)
			d, err := a.AuthorizeBatched(ctx, r, loader, cedar.BatchedOptions{MaxIterations: 1})
			if d != cedar.Deny {
				t.Fatal("malformed batched request allowed")
			}
			requireUTF8InputError(t, err)
			resp, err = continuation.Reauthorize(ctx, r)
			if resp.Decision != cedar.Deny {
				t.Fatal("malformed continuation allowed")
			}
			requireUTF8InputError(t, err)
			_, err = rt.SliceEntities(ctx, cedar.SliceConfig{Schema: schema, Policies: policies}, r)
			requireUTF8InputError(t, err)
			partial := cedar.PartialRequest{Principal: cedar.KnownEntityUID(r.Principal), Action: r.Action, Resource: cedar.KnownEntityUID(r.Resource), Context: &r.Context}
			if name == "entities" {
				partial.Entities = cedar.NewPartialEntities(cedar.PartialEntity{UID: cedar.NewEntityUID("User", bad)})
			}
			if name == "raw entities" {
				partial.Entities = cedar.PartialEntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))
			}
			presp, err := a.PartialAuthorize(ctx, partial)
			if presp.Decision != cedar.Undecided {
				t.Fatal("malformed partial request decided")
			}
			requireUTF8InputError(t, err)
		})
	}
	_, err = a.PartialAuthorize(ctx, cedar.PartialRequest{Principal: cedar.UnknownEntityUID(bad), Action: req.Action, Resource: p.Resource})
	requireUTF8InputError(t, err)
}

func TestRejectInvalidUTF8Sources(t *testing.T) {
	ctx := context.Background()
	rt := testRuntime(t)
	bad := string([]byte{0xff})
	goodSchema := cedar.SchemaFromCedar(partialSchema)
	goodPolicies := cedar.PoliciesFromCedar(`permit(principal, action, resource);`)
	for _, schema := range []cedar.Schema{cedar.SchemaFromCedar(bad), cedar.SchemaFromJSON([]byte(`{"` + bad + `":{}}`))} {
		a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: goodPolicies})
		if a != nil {
			a.Close()
			t.Fatal("malformed schema loaded")
		}
		requireUTF8InputError(t, err)
		_, err = rt.Validate(ctx, schema, goodPolicies)
		requireUTF8InputError(t, err)
		_, err = rt.SliceEntities(ctx, cedar.SliceConfig{Schema: schema, Policies: goodPolicies}, cedar.Request{})
		requireUTF8InputError(t, err)
	}
	for _, policies := range []cedar.PolicySet{cedar.PoliciesFromCedar("//" + bad + "\npermit(principal, action, resource);"), cedar.PoliciesFromJSON([]byte(`{"policies":{"` + bad + `":{}}}`))} {
		a, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: policies})
		if a != nil {
			a.Close()
			t.Fatal("malformed policies loaded")
		}
		requireUTF8InputError(t, err)
		_, err = rt.Validate(ctx, goodSchema, policies)
		requireUTF8InputError(t, err)
		_, err = rt.SliceEntities(ctx, cedar.SliceConfig{Schema: goodSchema, Policies: policies}, cedar.Request{})
		requireUTF8InputError(t, err)
	}
}
