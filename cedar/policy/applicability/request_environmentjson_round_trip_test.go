package applicability_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	applicability "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/applicability"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	reflect "reflect"
	testing "testing"
)

func TestRequestEnvironmentJSONRoundTrip(t *testing.T) {
	principalSlot, resourceSlot := "A::Z", "Photo"
	want := applicability.PolicyApplicability{
		Policies: map[string][]cedarschema.RequestEnvironment{"policy": {{
			PrincipalType: "A::Z", Action: entityuid.NewEntityUID("NS::Action", "view 雪"), ResourceType: "Photo",
			PrincipalSlotType: &principalSlot, ResourceSlotType: &resourceSlot,
		}}},
		Templates: map[string][]cedarschema.RequestEnvironment{},
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got applicability.PolicyApplicability
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata JSON lost identity: %s -> %+v", data, got)
	}
}

func TestRequestEnvironmentJSONRejectsInvalidUTF8(t *testing.T) {
	bad := string([]byte{0xff})
	valid := cedarschema.RequestEnvironment{PrincipalType: "User", Action: entityuid.NewEntityUID("Action", "view"), ResourceType: "Photo"}
	for _, change := range []func(*cedarschema.RequestEnvironment){
		func(env *cedarschema.RequestEnvironment) { env.PrincipalType = bad },
		func(env *cedarschema.RequestEnvironment) { env.ResourceType = bad },
		func(env *cedarschema.RequestEnvironment) { env.Action.ID = bad },
		func(env *cedarschema.RequestEnvironment) { env.Action.Type = bad },
		func(env *cedarschema.RequestEnvironment) { env.PrincipalSlotType = &bad },
		func(env *cedarschema.RequestEnvironment) { env.ResourceSlotType = &bad },
	} {
		env := valid
		change(&env)
		if data, err := json.Marshal(env); err == nil || data != nil {
			t.Fatalf("metadata JSON replaced invalid UTF-8: %s %v", data, err)
		}
	}
}

func TestApplicabilityDoesNotAuthorize(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {}};`)
	policies := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when {principal == User::"alice"};`)
	metadata, err := rt.Applicability().ApplicableEnvironments(ctx, schema, policies)
	if err != nil || len(metadata.Policies["policy0"]) != 1 {
		t.Fatalf("metadata %+v %v", metadata, err)
	}
	auth, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	response, err := auth.Authorize(ctx, cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "bob"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "x")})
	if err != nil || response.Decision != cedarrequest.Deny {
		t.Fatalf("metadata granted access: %+v %v", response, err)
	}
}

func TestApplicabilityBoundaries(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	got, err := rt.Applicability().ApplicableEnvironments(ctx, cedarschema.SchemaFromJSON([]byte(`{}`)), cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource);`))
	if err != nil || len(got.Policies["policy0"]) != 0 {
		t.Fatalf("empty schema %+v %v", got, err)
	}
	for _, tc := range []struct {
		Schema   cedarschema.Schema
		policies cedarpolicy.PolicySet
		kind     diagnostic.ErrorKind
	}{
		{cedarschema.SchemaFromCedar("not a schema"), cedarpolicy.PolicySet{}, diagnostic.KindSchema},
		{cedarschema.SchemaFromJSON([]byte(`{}`)), cedarpolicy.PoliciesFromCedar("not a policy"), diagnostic.KindPolicies},
		{cedarschema.SchemaFromCedar(string([]byte{0xff})), cedarpolicy.PolicySet{}, diagnostic.KindInput},
		{cedarschema.SchemaFromJSON([]byte(`{}`)), cedarpolicy.PoliciesFromCedar(string([]byte{0xff})), diagnostic.KindInput},
	} {
		_, err := rt.Applicability().ApplicableEnvironments(ctx, tc.Schema, tc.policies)
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != tc.kind {
			t.Fatalf("want %s: %v", tc.kind, err)
		}
	}
}
