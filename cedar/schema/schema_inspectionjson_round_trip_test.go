package schema_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	reflect "reflect"
	strings "strings"
	testing "testing"
)

func TestSchemaInspectionJSONRoundTrip(t *testing.T) {
	slotType := "App::User"
	action := entityuid.NewEntityUID("App::Action", "read/雪")
	inspection := cedarschema.SchemaInspection{
		ResolvedSchema: json.RawMessage(`{"App":{}}`),
		ExpandedSchema: json.RawMessage(`{"App":{}}`),
		Ancestors:      map[string][]string{"App::User": {"App::Group"}},
		Actions:        []entityuid.EntityUID{action},
		ActionGroups:   []entityuid.EntityUID{entityuid.NewEntityUID("App::Action", "all")},
		Environments: []cedarschema.RequestEnvironment{{
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
	var reparsed cedarschema.SchemaInspection
	if err := json.Unmarshal(data, &reparsed); err != nil || !reflect.DeepEqual(inspection, reparsed) {
		t.Fatalf("inspection JSON round-trip changed data: %+v %v", reparsed, err)
	}
}

func TestSchemaCompositionResolvesAfterCombining(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	first := cedarschema.SchemaFragmentFromCedar(`entity User {profile: Profile}; entity Photo; action view appliesTo {principal: User, resource: Photo};`)
	second := cedarschema.SchemaFragmentFromCedar(`type Profile = {name: String};`)
	_, err := rt.Schemas().ComposeSchema(ctx, first)
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindSchema {
		t.Fatalf("missing declaration accepted: %v", err)
	}
	schema, err := rt.Schemas().ComposeSchema(ctx, first, second)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := rt.Schemas().InspectSchema(ctx, schema)
	if err != nil || !strings.Contains(string(inspection.ResolvedSchema), `"type":"Profile"`) || strings.Contains(string(inspection.ResolvedSchema), `"EntityOrCommon"`) || strings.Contains(string(inspection.ExpandedSchema), `"Profile"`) {
		t.Fatalf("type resolution: %+v %v", inspection, err)
	}
	entities := cedarentity.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"alice"},"attrs":{"profile":{"name":"Alice"}},"parents":[]},{"uid":{"type":"Photo","id":"one"},"attrs":{},"parents":[]}]`))
	authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { principal.profile.name == "Alice" };`), Entities: entities})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "one")})
	if err != nil || response.Decision != cedarrequest.Allow {
		t.Fatalf("composed schema authorization: %+v %v", response, err)
	}
}

func TestSchemaFragmentAnnotations(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	fragment := cedarschema.SchemaFragmentFromCedar(`@doc("雪") namespace App { @doc("person") entity User { @doc("label") name: String }; action view appliesTo {principal: User, resource: User}; }`)
	jsonForm, err := rt.Schemas().ConvertSchemaFragment(ctx, fragment, syntax.FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	cedarForm, err := rt.Schemas().ConvertSchemaFragment(ctx, jsonForm, syntax.FormatCedar)
	if err != nil {
		t.Fatal(err)
	}
	back, err := rt.Schemas().ConvertSchemaFragment(ctx, cedarForm, syntax.FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	first, err := rt.Schemas().ComposeSchema(ctx, jsonForm)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rt.Schemas().ComposeSchema(ctx, back)
	if err != nil {
		t.Fatal(err)
	}
	original, err := rt.Schemas().InspectSchema(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := rt.Schemas().InspectSchema(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	jsonassert.Equal(t, original.ExpandedSchema, reparsed.ExpandedSchema)
	if !strings.Contains(cedarForm.Text(), "雪") || !strings.Contains(back.Text(), "person") || !strings.Contains(back.Text(), "label") {
		t.Fatal("Unicode annotation changed")
	}
}
