package cedar_test

import (
	"context"
	"errors"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzSchemaFragments(f *testing.F) {
	f.Add("entity User;", "entity Photo;", false)
	f.Add("entity User {profile: Profile};", "type Profile = {name: String};", false)
	f.Add(`{"":{"entityTypes":{"User":{}},"actions":{}}}`, `{}`, true)
	f.Add("", "", false)
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, first, second string, jsonFormat bool) {
		if len(first)+len(second) > 4096 {
			t.Skip()
		}
		fragments := []cedar.SchemaFragment{cedar.SchemaFragmentFromCedar(first), cedar.SchemaFragmentFromCedar(second)}
		if jsonFormat {
			fragments = []cedar.SchemaFragment{cedar.SchemaFragmentFromJSON([]byte(first)), cedar.SchemaFragmentFromJSON([]byte(second))}
		}
		schema, err := rt.ComposeSchema(context.Background(), fragments...)
		if err != nil {
			var ce *cedar.Error
			if !errors.As(err, &ce) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if _, err := rt.InspectSchema(context.Background(), schema); err != nil {
			t.Fatalf("composed schema cannot be inspected: %v", err)
		}
		if _, err := rt.ActionEntities(context.Background(), schema); err != nil {
			t.Fatalf("composed schema cannot supply action entities: %v", err)
		}
	})
}
