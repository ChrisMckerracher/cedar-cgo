package schema_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	sort "sort"
	testing "testing"
)

func TestSchemaNativeFixtures(t *testing.T) {
	var cases []struct {
		Name      string
		Fragments []struct{ Format, Text string }
		Policies  string
	}
	var expected []struct {
		Name        string
		Error       bool
		Conversions []struct {
			JSON  json.RawMessage `json:"json"`
			Cedar string
		}
		Inspection     cedarschema.SchemaInspection
		ActionEntities json.RawMessage `json:"action_entities"`
		Valid          bool
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/schemas/input.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/schemas/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(expected) {
		t.Fatal("fixture count differs")
	}
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	for i, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			want := expected[i]
			fragments := make([]cedarschema.SchemaFragment, len(test.Fragments))
			if want.Error {
				for j, source := range test.Fragments {
					fragments[j] = cedarschema.SchemaFragmentFromCedar(source.Text)
				}
				_, err := rt.Schemas().ComposeSchema(ctx, fragments...)
				var ce *diagnostic.Error
				if !errors.As(err, &ce) || ce.Kind != diagnostic.KindSchema {
					t.Fatalf("native composition error: %v", err)
				}
				return
			}
			for j, source := range test.Fragments {
				fragments[j] = cedarschema.SchemaFragmentFromCedar(source.Text)
				if source.Format == "json" {
					fragments[j] = cedarschema.SchemaFragmentFromJSON([]byte(source.Text))
				}
				converted, err := rt.Schemas().ConvertSchemaFragment(ctx, fragments[j], syntax.FormatJSON)
				if err != nil {
					t.Fatal(err)
				}
				testsupport.AssertSchemaJSON(t, []byte(converted.Text()), want.Conversions[j].JSON)
				cedarForm, err := rt.Schemas().ConvertSchemaFragment(ctx, converted, syntax.FormatCedar)
				if err != nil {
					t.Fatal(err)
				}
				if cedarForm.Text() != want.Conversions[j].Cedar || cedarForm.Format() != syntax.FormatCedar {
					t.Fatalf("Cedar conversion: %s", cedarForm.Text())
				}
			}
			schema, err := rt.Schemas().ComposeSchema(ctx, fragments...)
			if err != nil {
				t.Fatal(err)
			}
			got, err := rt.Schemas().InspectSchema(ctx, schema)
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var reparsed cedarschema.SchemaInspection
			if err := json.Unmarshal(gotJSON, &reparsed); err != nil || !reflect.DeepEqual(got, reparsed) {
				t.Fatalf("inspection JSON round-trip changed data: %+v %v", reparsed, err)
			}
			wantJSON, err := json.Marshal(want.Inspection)
			if err != nil {
				t.Fatal(err)
			}
			testsupport.AssertSchemaJSON(t, gotJSON, wantJSON)
			entities, err := rt.Schemas().ActionEntities(ctx, schema)
			if err != nil {
				t.Fatal(err)
			}
			var entityList []json.RawMessage
			entityJSON, err := json.Marshal(entities)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(entityJSON, &entityList); err != nil {
				t.Fatal(err)
			}
			sort.Slice(entityList, func(a, b int) bool {
				var left, right struct{ UID entityuid.EntityUID }
				if err := json.Unmarshal(entityList[a], &left); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(entityList[b], &right); err != nil {
					t.Fatal(err)
				}
				return left.UID.Type < right.UID.Type || left.UID.Type == right.UID.Type && left.UID.ID < right.UID.ID
			})
			actualEntities, err := json.Marshal(entityList)
			if err != nil {
				t.Fatal(err)
			}
			testsupport.AssertSchemaJSON(t, actualEntities, want.ActionEntities)
			validation, err := rt.Validation().Validate(ctx, schema, cedarpolicy.PoliciesFromCedar(test.Policies))
			if err != nil || validation.Passed != want.Valid {
				t.Fatalf("composed validation: %+v %v", validation, err)
			}
		})
	}
}
