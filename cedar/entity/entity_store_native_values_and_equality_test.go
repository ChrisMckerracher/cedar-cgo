package entity_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	time "time"
)

func TestEntityStoreNativeValuesAndEquality(t *testing.T) {
	rt, ctx := testsupport.TestRuntime(t), context.Background()
	uid := entityuid.NewEntityUID("User", "雪")
	store, err := rt.Entities().ParseEntityStore(ctx, cedarentity.NewEntities(cedarentity.Entity{UID: uid, Attrs: cedarvalue.Record{"n": cedarvalue.Long(9223372036854775807), "ip": cedarvalue.IPAddr("10.0.0.1")}, Tags: cedarvalue.Record{"tag": cedarvalue.String("雪")}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	entity, found, err := store.Get(ctx, uid)
	if err != nil || !found {
		t.Fatalf("get %v %v", found, err)
	}
	if entity.Attrs["n"] != cedarvalue.Long(9223372036854775807) || entity.Attrs["ip"] != cedarvalue.ExtensionValue(`ip("10.0.0.1")`) || entity.Tags["tag"] != cedarvalue.String("雪") {
		t.Fatalf("values %+v %+v", entity.Attrs, entity.Tags)
	}
	changed, err := store.Upsert(ctx, cedarentity.NewEntities(cedarentity.Entity{UID: uid, Attrs: cedarvalue.Record{"n": cedarvalue.Long(1)}}))
	if err != nil {
		t.Fatal(err)
	}
	equal, err := store.DeepEqual(ctx, changed)
	if err != nil || equal {
		t.Fatalf("changed attribute equality %v %v", equal, err)
	}
	entity.Attrs["n"] = cedarvalue.Long(0)
	again, _, err := store.Get(ctx, uid)
	if err != nil || again.Attrs["n"] != cedarvalue.Long(9223372036854775807) {
		t.Fatal("returned values modified store")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.Get(canceled, uid); err == nil {
		t.Fatal("canceled context accepted")
	}
	if _, _, err := store.Get(ctx, uid); err != nil {
		t.Fatal("cancellation modified snapshot", err)
	}
}

func TestEntityStoreZeroAndInvalidInputs(t *testing.T) {
	var zero cedarentity.ParsedEntityStore
	if _, err := zero.Remove(context.Background()); err == nil {
		t.Fatal("zero store accepted")
	}
	rt := testsupport.TestRuntime(t)
	if _, err := rt.Entities().ParseEntityStore(context.Background(), cedarentity.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"a"},"parents":[{"type":"User","id":"a"}],"attrs":{}}]`)), nil); err == nil {
		t.Fatal("cycle accepted")
	}
	store, err := rt.Entities().ParseEntityStore(context.Background(), cedarentity.Entities{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeepEqual(context.Background(), zero); err == nil {
		t.Fatal("zero comparison accepted")
	}
	if _, _, err := store.Get(context.Background(), entityuid.NewEntityUID("User", string([]byte{255}))); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func FuzzEntityStoreUnrelatedDecisions(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{1, 255})
	rt := testsupport.TestRuntime(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		uid := func(typ, id string) entityuid.EntityUID { return entityuid.NewEntityUID(typ, id) }
		safe, allowed := uid("User", "safe"), uid("Group", "allowed")
		a, b, c := uid("Node", "a"), uid("Node", "b"), uid("Node", "c")
		enabled := len(data) == 0 || data[0]%2 == 0
		store, err := rt.Entities().ParseEntityStore(ctx, cedarentity.NewEntities(cedarentity.Entity{UID: safe, Parents: []entityuid.EntityUID{allowed}, Attrs: cedarvalue.Record{"enabled": cedarvalue.Bool(enabled)}}, cedarentity.Entity{UID: allowed}, cedarentity.Entity{UID: a, Parents: []entityuid.EntityUID{b}}, cedarentity.Entity{UID: b, Parents: []entityuid.EntityUID{c}}, cedarentity.Entity{UID: c}), nil)
		if err != nil {
			t.Fatal(err)
		}
		policies := cedarpolicy.PoliciesFromCedar(`permit(principal in Group::"allowed", action, resource) when { principal.enabled };`)
		decision := func(store cedarentity.ParsedEntityStore) cedarrequest.Decision {
			authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: policies, Entities: store.Export(), Limits: testsupport.FuzzLimits})
			if err != nil {
				t.Fatal(err)
			}
			defer authorizer.Close()
			result, err := authorizer.Authorize(ctx, cedarrequest.Request{Principal: safe, Action: uid("Action", "view"), Resource: uid("Document", "safe")})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Errors) != 0 {
				t.Fatal(result.Errors)
			}
			return result.Decision
		}
		before := decision(store)
		for _, value := range data {
			if value%2 == 0 {
				store, err = store.Remove(ctx, b)
			} else {
				store, err = store.Upsert(ctx, cedarentity.NewEntities(cedarentity.Entity{UID: b, Parents: []entityuid.EntityUID{c}, Attrs: cedarvalue.Record{"n": cedarvalue.Long(value)}}))
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if after := decision(store); after != before {
			t.Fatalf("unrelated decision changed %s -> %s", before, after)
		}
	})
}
