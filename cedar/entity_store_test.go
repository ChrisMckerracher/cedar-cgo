package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func equalJSON(t testing.TB, got, want []byte) {
	t.Helper()
	if !reflect.DeepEqual(entityStoreJSON(t, got), entityStoreJSON(t, want)) {
		t.Fatalf("JSON differs\ngot %s\nwant %s", got, want)
	}
}

func entityStoreJSON(t testing.TB, data []byte) any {
	t.Helper()
	if !json.Valid(data) {
		t.Fatalf("invalid JSON: %s", data)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestEntityStoreJSONComparisonPreservesIntegers(t *testing.T) {
	for _, numbers := range [][2]string{
		{"9007199254740992", "9007199254740993"},
		{"9223372036854775806", "9223372036854775807"},
		{"-9223372036854775808", "-9223372036854775807"},
	} {
		left := []byte(`{"attrs":{"n":` + numbers[0] + `}}`)
		right := []byte(`{"attrs":{"n":` + numbers[1] + `}}`)
		if reflect.DeepEqual(entityStoreJSON(t, left), entityStoreJSON(t, right)) {
			t.Fatalf("different integers compare equal: %s and %s", left, right)
		}
		equalJSON(t, left, left)
	}
}

func TestEntityStoreNativeParity(t *testing.T) {
	rt, ctx := testRuntime(t), context.Background()
	var cases []struct {
		Name     string
		Schema   *string
		Entities json.RawMessage
		UID      cedar.EntityUID
		Ancestor cedar.EntityUID
		Steps    []struct {
			Operation string
			UIDs      []cedar.EntityUID
			Entities  json.RawMessage
		}
	}
	var expected []struct {
		Name   string
		Stages []struct {
			ErrorKind cedar.ErrorKind `json:"error_kind"`
			Result    struct {
				Normalized json.RawMessage
				Entity     json.RawMessage
				Parents    []cedar.EntityUID
				Ancestors  []cedar.EntityUID
				IsAncestor bool `json:"is_ancestor"`
				DeepEqual  bool `json:"normalized_deep_equal"`
			}
		}
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/entity-store/input.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/entity-store/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(expected) {
		t.Fatal("fixture count differs")
	}
	for i, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			var schema *cedar.Schema
			if test.Schema != nil {
				value := cedar.SchemaFromCedar(*test.Schema)
				schema = &value
			}
			store, err := rt.ParseEntityStore(ctx, cedar.EntitiesFromJSON(test.Entities), schema)
			if err != nil {
				t.Fatal(err)
			}
			if expected[i].Name != test.Name || len(expected[i].Stages) != len(test.Steps)+1 {
				t.Fatal("fixture stages differ")
			}
			original := store
			for index, want := range expected[i].Stages {
				if index > 0 {
					step := test.Steps[index-1]
					var changed cedar.ParsedEntityStore
					if step.Operation == "remove" {
						changed, err = store.Remove(ctx, step.UIDs...)
					} else {
						changed, err = store.Upsert(ctx, cedar.EntitiesFromJSON(step.Entities))
					}
					if want.ErrorKind != "" {
						var input *cedar.Error
						if !errors.As(err, &input) || input.Kind != want.ErrorKind {
							t.Fatalf("stage %d: wanted %s, got %v", index, want.ErrorKind, err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						store = changed
					}
				}
				export, err := json.Marshal(store.Export())
				if err != nil {
					t.Fatal(err)
				}
				equalJSON(t, export, want.Result.Normalized)
				entity, found, err := store.Get(ctx, test.UID)
				if err != nil {
					t.Fatal(err)
				}
				if found != (string(want.Result.Entity) != "null") {
					t.Fatalf("stage %d: found %v", index, found)
				}
				if found {
					equalJSON(t, entity.JSON(), want.Result.Entity)
					if !reflect.DeepEqual(entity.Parents, want.Result.Parents) {
						t.Fatalf("direct parents %+v, want %+v", entity.Parents, want.Result.Parents)
					}
				}
				ancestors, found, err := store.Ancestors(ctx, test.UID)
				if err != nil {
					t.Fatal(err)
				}
				if found != (want.Result.Ancestors != nil) || !reflect.DeepEqual(ancestors, want.Result.Ancestors) {
					t.Fatalf("ancestors %+v, found %v, want %+v", ancestors, found, want.Result.Ancestors)
				}
				answer, err := store.IsAncestorOf(ctx, test.Ancestor, test.UID)
				if err != nil || answer != want.Result.IsAncestor {
					t.Fatalf("ancestry %v %v", answer, err)
				}
				reparsed, err := rt.ParseEntityStore(ctx, store.Export(), nil)
				if err != nil {
					t.Fatal(err)
				}
				answer, err = store.DeepEqual(ctx, reparsed)
				if err != nil || answer != want.Result.DeepEqual {
					t.Fatalf("deep equality %v %v", answer, err)
				}
			}
			// Every mutation leaves the original graph available.
			initial, err := json.Marshal(original.Export())
			if err != nil {
				t.Fatal(err)
			}
			equalJSON(t, initial, expected[i].Stages[0].Result.Normalized)
		})
	}
}

func TestEntityStoreNativeValuesAndEquality(t *testing.T) {
	rt, ctx := testRuntime(t), context.Background()
	uid := cedar.NewEntityUID("User", "雪")
	store, err := rt.ParseEntityStore(ctx, cedar.NewEntities(cedar.Entity{UID: uid, Attrs: cedar.Record{"n": cedar.Long(9223372036854775807), "ip": cedar.IPAddr("10.0.0.1")}, Tags: cedar.Record{"tag": cedar.String("雪")}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	entity, found, err := store.Get(ctx, uid)
	if err != nil || !found {
		t.Fatalf("get %v %v", found, err)
	}
	if entity.Attrs["n"] != cedar.Long(9223372036854775807) || entity.Attrs["ip"] != cedar.ExtensionValue(`ip("10.0.0.1")`) || entity.Tags["tag"] != cedar.String("雪") {
		t.Fatalf("values %+v %+v", entity.Attrs, entity.Tags)
	}
	changed, err := store.Upsert(ctx, cedar.NewEntities(cedar.Entity{UID: uid, Attrs: cedar.Record{"n": cedar.Long(1)}}))
	if err != nil {
		t.Fatal(err)
	}
	equal, err := store.DeepEqual(ctx, changed)
	if err != nil || equal {
		t.Fatalf("changed attribute equality %v %v", equal, err)
	}
	entity.Attrs["n"] = cedar.Long(0)
	again, _, err := store.Get(ctx, uid)
	if err != nil || again.Attrs["n"] != cedar.Long(9223372036854775807) {
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
	var zero cedar.ParsedEntityStore
	if _, err := zero.Remove(context.Background()); err == nil {
		t.Fatal("zero store accepted")
	}
	rt := testRuntime(t)
	if _, err := rt.ParseEntityStore(context.Background(), cedar.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"a"},"parents":[{"type":"User","id":"a"}],"attrs":{}}]`)), nil); err == nil {
		t.Fatal("cycle accepted")
	}
	store, err := rt.ParseEntityStore(context.Background(), cedar.Entities{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeepEqual(context.Background(), zero); err == nil {
		t.Fatal("zero comparison accepted")
	}
	if _, _, err := store.Get(context.Background(), cedar.NewEntityUID("User", string([]byte{255}))); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func FuzzEntityStoreUnrelatedDecisions(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{1, 255})
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		uid := func(typ, id string) cedar.EntityUID { return cedar.NewEntityUID(typ, id) }
		safe, allowed := uid("User", "safe"), uid("Group", "allowed")
		a, b, c := uid("Node", "a"), uid("Node", "b"), uid("Node", "c")
		enabled := len(data) == 0 || data[0]%2 == 0
		store, err := rt.ParseEntityStore(ctx, cedar.NewEntities(cedar.Entity{UID: safe, Parents: []cedar.EntityUID{allowed}, Attrs: cedar.Record{"enabled": cedar.Bool(enabled)}}, cedar.Entity{UID: allowed}, cedar.Entity{UID: a, Parents: []cedar.EntityUID{b}}, cedar.Entity{UID: b, Parents: []cedar.EntityUID{c}}, cedar.Entity{UID: c}), nil)
		if err != nil {
			t.Fatal(err)
		}
		policies := cedar.PoliciesFromCedar(`permit(principal in Group::"allowed", action, resource) when { principal.enabled };`)
		decision := func(store cedar.ParsedEntityStore) cedar.Decision {
			authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: policies, Entities: store.Export(), Limits: fuzzLimits})
			if err != nil {
				t.Fatal(err)
			}
			defer authorizer.Close()
			result, err := authorizer.Authorize(ctx, cedar.Request{Principal: safe, Action: uid("Action", "view"), Resource: uid("Document", "safe")})
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
				store, err = store.Upsert(ctx, cedar.NewEntities(cedar.Entity{UID: b, Parents: []cedar.EntityUID{c}, Attrs: cedar.Record{"n": cedar.Long(value)}}))
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
