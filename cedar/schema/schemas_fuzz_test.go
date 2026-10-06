package schema_test

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func FuzzSchemaFragments(f *testing.F) {
	f.Add("entity User;", "entity Photo;", false)
	f.Add("entity User {profile: Profile};", "type Profile = {name: String};", false)
	f.Add(`{"":{"entityTypes":{"User":{}},"actions":{}}}`, `{}`, true)
	f.Add("", "", false)
	rt := testruntime.New(f)
	f.Fuzz(func(t *testing.T, first, second string, jsonFormat bool) {
		if len(first)+len(second) > 4096 {
			t.Skip()
		}
		fragments := []cedarschema.SchemaFragment{cedarschema.SchemaFragmentFromCedar(first), cedarschema.SchemaFragmentFromCedar(second)}
		if jsonFormat {
			fragments = []cedarschema.SchemaFragment{cedarschema.SchemaFragmentFromJSON([]byte(first)), cedarschema.SchemaFragmentFromJSON([]byte(second))}
		}
		schema, err := rt.Schemas().ComposeSchema(context.Background(), fragments...)
		if err != nil {
			var ce *diagnostic.Error
			if !errors.As(err, &ce) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if _, err := rt.Schemas().InspectSchema(context.Background(), schema); err != nil {
			t.Fatalf("composed schema cannot be inspected: %v", err)
		}
		if _, err := rt.Schemas().ActionEntities(context.Background(), schema); err != nil {
			t.Fatalf("composed schema cannot supply action entities: %v", err)
		}
	})
}
