package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
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
		Inspection     cedar.SchemaInspection
		ActionEntities json.RawMessage `json:"action_entities"`
		Valid          bool
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/schemas/input.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/schemas/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(expected) {
		t.Fatal("fixture count differs")
	}
	rt := testRuntime(t)
	ctx := context.Background()
	for i, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			want := expected[i]
			fragments := make([]cedar.SchemaFragment, len(test.Fragments))
			if want.Error {
				for j, source := range test.Fragments {
					fragments[j] = cedar.SchemaFragmentFromCedar(source.Text)
				}
				_, err := rt.ComposeSchema(ctx, fragments...)
				var ce *cedar.Error
				if !errors.As(err, &ce) || ce.Kind != cedar.KindSchema {
					t.Fatalf("native composition error: %v", err)
				}
				return
			}
			for j, source := range test.Fragments {
				fragments[j] = cedar.SchemaFragmentFromCedar(source.Text)
				if source.Format == "json" {
					fragments[j] = cedar.SchemaFragmentFromJSON([]byte(source.Text))
				}
				converted, err := rt.ConvertSchemaFragment(ctx, fragments[j], cedar.FormatJSON)
				if err != nil {
					t.Fatal(err)
				}
				assertSchemaJSON(t, []byte(converted.Text()), want.Conversions[j].JSON)
				cedarForm, err := rt.ConvertSchemaFragment(ctx, converted, cedar.FormatCedar)
				if err != nil {
					t.Fatal(err)
				}
				if cedarForm.Text() != want.Conversions[j].Cedar || cedarForm.Format() != cedar.FormatCedar {
					t.Fatalf("Cedar conversion: %s", cedarForm.Text())
				}
			}
			schema, err := rt.ComposeSchema(ctx, fragments...)
			if err != nil {
				t.Fatal(err)
			}
			got, err := rt.InspectSchema(ctx, schema)
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var reparsed cedar.SchemaInspection
			if err := json.Unmarshal(gotJSON, &reparsed); err != nil || !reflect.DeepEqual(got, reparsed) {
				t.Fatalf("inspection JSON round-trip changed data: %+v %v", reparsed, err)
			}
			wantJSON, err := json.Marshal(want.Inspection)
			if err != nil {
				t.Fatal(err)
			}
			assertSchemaJSON(t, gotJSON, wantJSON)
			entities, err := rt.ActionEntities(ctx, schema)
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
				var left, right struct{ UID cedar.EntityUID }
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
			assertSchemaJSON(t, actualEntities, want.ActionEntities)
			validation, err := rt.Validate(ctx, schema, cedar.PoliciesFromCedar(test.Policies))
			if err != nil || validation.Passed != want.Valid {
				t.Fatalf("composed validation: %+v %v", validation, err)
			}
		})
	}
}

func TestSchemaInspectionJSONRoundTrip(t *testing.T) {
	slotType := "App::User"
	action := cedar.NewEntityUID("App::Action", "read/雪")
	inspection := cedar.SchemaInspection{
		ResolvedSchema: json.RawMessage(`{"App":{}}`),
		ExpandedSchema: json.RawMessage(`{"App":{}}`),
		Ancestors:      map[string][]string{"App::User": {"App::Group"}},
		Actions:        []cedar.EntityUID{action},
		ActionGroups:   []cedar.EntityUID{cedar.NewEntityUID("App::Action", "all")},
		Environments: []cedar.RequestEnvironment{{
			PrincipalType: "App::User", Action: action, ResourceType: "App::Photo", PrincipalSlotType: &slotType,
		}},
	}
	data, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "__entity") || !strings.Contains(string(data), `"actions":[{"type":"App::Action","id":"read/雪"}]`) {
		t.Fatalf("schema inspection UIDs are not flat: %s", data)
	}
	var reparsed cedar.SchemaInspection
	if err := json.Unmarshal(data, &reparsed); err != nil || !reflect.DeepEqual(inspection, reparsed) {
		t.Fatalf("inspection JSON round-trip changed data: %+v %v", reparsed, err)
	}
}

func assertSchemaJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b any
	gotDecoder := json.NewDecoder(bytes.NewReader(got))
	gotDecoder.UseNumber()
	if err := gotDecoder.Decode(&a); err != nil {
		t.Fatal(err)
	}
	wantDecoder := json.NewDecoder(bytes.NewReader(want))
	wantDecoder.UseNumber()
	if err := wantDecoder.Decode(&b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("JSON differs\ngot: %s\nwant: %s", got, want)
	}
}

func TestSchemaCompositionResolvesAfterCombining(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	first := cedar.SchemaFragmentFromCedar(`entity User {profile: Profile}; entity Photo; action view appliesTo {principal: User, resource: Photo};`)
	second := cedar.SchemaFragmentFromCedar(`type Profile = {name: String};`)
	_, err := rt.ComposeSchema(ctx, first)
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindSchema {
		t.Fatalf("missing declaration accepted: %v", err)
	}
	schema, err := rt.ComposeSchema(ctx, first, second)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := rt.InspectSchema(ctx, schema)
	if err != nil || !strings.Contains(string(inspection.ResolvedSchema), `"type":"Profile"`) || strings.Contains(string(inspection.ResolvedSchema), `"EntityOrCommon"`) || strings.Contains(string(inspection.ExpandedSchema), `"Profile"`) {
		t.Fatalf("type resolution: %+v %v", inspection, err)
	}
	entities := cedar.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"alice"},"attrs":{"profile":{"name":"Alice"}},"parents":[]},{"uid":{"type":"Photo","id":"one"},"attrs":{},"parents":[]}]`))
	authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource) when { principal.profile.name == "Alice" };`), Entities: entities})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "one")})
	if err != nil || response.Decision != cedar.Allow {
		t.Fatalf("composed schema authorization: %+v %v", response, err)
	}
}

func TestSchemaFragmentAnnotations(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	fragment := cedar.SchemaFragmentFromCedar(`@doc("雪") namespace App { @doc("person") entity User { @doc("label") name: String }; action view appliesTo {principal: User, resource: User}; }`)
	jsonForm, err := rt.ConvertSchemaFragment(ctx, fragment, cedar.FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	cedarForm, err := rt.ConvertSchemaFragment(ctx, jsonForm, cedar.FormatCedar)
	if err != nil {
		t.Fatal(err)
	}
	back, err := rt.ConvertSchemaFragment(ctx, cedarForm, cedar.FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	first, err := rt.ComposeSchema(ctx, jsonForm)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rt.ComposeSchema(ctx, back)
	if err != nil {
		t.Fatal(err)
	}
	original, err := rt.InspectSchema(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := rt.InspectSchema(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaJSON(t, original.ExpandedSchema, reparsed.ExpandedSchema)
	if !strings.Contains(cedarForm.Text(), "雪") || !strings.Contains(back.Text(), "person") || !strings.Contains(back.Text(), "label") {
		t.Fatal("Unicode annotation changed")
	}
}

func TestSchemaErrors(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	for _, test := range []struct {
		Fragments []cedar.SchemaFragment
		Kind      cedar.ErrorKind
	}{
		{[]cedar.SchemaFragment{cedar.SchemaFragmentFromCedar("invalid")}, cedar.KindSchema},
		{[]cedar.SchemaFragment{cedar.SchemaFragmentFromJSON([]byte(`{}`)), cedar.SchemaFragmentFromCedar(string([]byte{0xff}))}, cedar.KindInput},
		{[]cedar.SchemaFragment{cedar.SchemaFragmentFromCedar("entity User;"), cedar.SchemaFragmentFromCedar("entity User;")}, cedar.KindSchema},
		{[]cedar.SchemaFragment{cedar.SchemaFragmentFromCedar("type A = B;"), cedar.SchemaFragmentFromCedar("type B = A;")}, cedar.KindSchema},
		{[]cedar.SchemaFragment{cedar.SchemaFragmentFromCedar("action A in B;"), cedar.SchemaFragmentFromCedar("action B in A;")}, cedar.KindSchema},
	} {
		_, err := rt.ComposeSchema(ctx, test.Fragments...)
		var ce *cedar.Error
		if !errors.As(err, &ce) || ce.Kind != test.Kind {
			t.Fatalf("composition error: %v", err)
		}
	}
	_, err := rt.ConvertSchemaFragment(ctx, cedar.SchemaFragmentFromCedar(""), cedar.Format(99))
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
		t.Fatalf("invalid format: %v", err)
	}
}

func TestSchemaCompositionNamespaceAnnotations(t *testing.T) {
	rt := testRuntime(t)
	schema, err := rt.ComposeSchema(context.Background(),
		cedar.SchemaFragmentFromCedar(`@doc("first") namespace App { entity User; }`),
		cedar.SchemaFragmentFromCedar(`@doc("second") namespace App { entity Photo; }`))
	if err != nil {
		t.Fatal(err)
	}
	var declarations map[string]struct {
		Annotations map[string]string
	}
	if err := json.Unmarshal([]byte(schema.Text()), &declarations); err != nil {
		t.Fatal(err)
	}
	if declarations["App"].Annotations["doc"] != "second" {
		t.Fatalf("namespace annotation order: %s", schema.Text())
	}
}
