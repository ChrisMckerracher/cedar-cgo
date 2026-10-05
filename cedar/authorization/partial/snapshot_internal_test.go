package partial

import (
	"bytes"
	"context"
	"errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	"sync"
	"testing"
)

func TestPartialTypedEntitiesAndSnapshot(t *testing.T) {
	ctx := context.Background()
	rt, err := execution.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	schema := cedarschema.SchemaFromCedar("entity User; entity Photo {private: Bool}; action view appliesTo {principal: User, resource: Photo, context: {}};")
	a, err := newClient(ctx, rt, TestConfig{
		Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar("permit(principal, action, resource) when { resource.private };"),
		Limits: execution.Limits{MaxInstances: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.session.Close()
	uid := entityuid.NewEntityUID("Photo", "one")
	empty := cedarvalue.Record{}
	req := PartialRequest{Principal: UnknownEntityUID("User"), Action: entityuid.NewEntityUID("Action", "view"), Resource: UnknownEntityUID("Photo")}
	req.Resource = KnownEntityUID(uid)
	req.Context = &cedarrequest.Context{}
	req.Entities = NewPartialEntities(PartialEntity{UID: uid, Parents: []entityuid.EntityUID{}, Tags: &empty})
	res, err := a.PartialAuthorize(ctx, req)
	if err != nil || res.Decision != Undecided {
		t.Fatalf("partial: %+v %v", res, err)
	}
	frozen, err := res.Export()
	if err != nil {
		t.Fatal(err)
	}
	*req.Resource.ID = "mutated"
	res.Decision = PartialAllow
	res.Residuals[0].Cedar = "permit(principal, action, resource);"
	after, err := res.Export()
	if err != nil || !bytes.Equal(frozen, after) {
		t.Fatalf("caller edits changed frozen input: %s %v", after, err)
	}
	imported, err := a.ImportPartialResponse(ctx, frozen)
	if err != nil {
		t.Fatal(err)
	}
	clear(frozen)
	concrete := cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: req.Action, Resource: uid,
		Entities: cedarentity.NewEntities(cedarentity.Entity{UID: uid, Attrs: cedarvalue.Record{"private": cedarvalue.Bool(false)}})}
	pooled, err := a.session.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = pooled.Value().Close(ctx)
	pooled.Release()
	failed, err := res.Reauthorize(ctx, concrete)
	if failed.Decision != cedarrequest.Deny || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("closed handle granted permission: %+v %v", failed, err)
	}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			r, err := res.Reauthorize(ctx, concrete)
			if err != nil || r.Decision != cedarrequest.Deny {
				t.Errorf("snapshot reauthorize: %+v %v", r, err)
			}
		})
	}
	wg.Wait()
	r, err := imported.Reauthorize(ctx, concrete)
	if err != nil || r.Decision != cedarrequest.Deny {
		t.Fatalf("import retained caller bytes: %+v %v", r, err)
	}
	if a.session.Stats().Created < 2 {
		t.Fatal("continuation did not survive instance replacement")
	}
}
