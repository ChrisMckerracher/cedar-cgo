package entity_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
)

func TestEntityStoreNativeParity(t *testing.T) {
	rt, ctx := testsupport.TestRuntime(t), context.Background()
	var cases []struct {
		Name     string
		Schema   *string
		Entities json.RawMessage
		UID      entityuid.EntityUID
		Ancestor entityuid.EntityUID
		Steps    []struct {
			Operation string
			UIDs      []entityuid.EntityUID
			Entities  json.RawMessage
		}
	}
	var expected []struct {
		Name   string
		Stages []struct {
			ErrorKind diagnostic.ErrorKind `json:"error_kind"`
			Result    struct {
				Normalized json.RawMessage
				Entity     json.RawMessage
				Parents    []entityuid.EntityUID
				Ancestors  []entityuid.EntityUID
				IsAncestor bool `json:"is_ancestor"`
				DeepEqual  bool `json:"normalized_deep_equal"`
			}
		}
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/entity-store/input.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/entity-store/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(expected) {
		t.Fatal("fixture count differs")
	}
	for i, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			var schema *cedarschema.Schema
			if test.Schema != nil {
				value := cedarschema.SchemaFromCedar(*test.Schema)
				schema = &value
			}
			store, err := rt.Entities().ParseEntityStore(ctx, cedarentity.EntitiesFromJSON(test.Entities), schema)
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
					var changed cedarentity.ParsedEntityStore
					if step.Operation == "remove" {
						changed, err = store.Remove(ctx, step.UIDs...)
					} else {
						changed, err = store.Upsert(ctx, cedarentity.EntitiesFromJSON(step.Entities))
					}
					if want.ErrorKind != "" {
						var input *diagnostic.Error
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
				testsupport.EqualJSON(t, export, want.Result.Normalized)
				entity, found, err := store.Get(ctx, test.UID)
				if err != nil {
					t.Fatal(err)
				}
				if found != (string(want.Result.Entity) != "null") {
					t.Fatalf("stage %d: found %v", index, found)
				}
				if found {
					testsupport.EqualJSON(t, entity.JSON(), want.Result.Entity)
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
				reparsed, err := rt.Entities().ParseEntityStore(ctx, store.Export(), nil)
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
			testsupport.EqualJSON(t, initial, expected[i].Stages[0].Result.Normalized)
		})
	}
}
