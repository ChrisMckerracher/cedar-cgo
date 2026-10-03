package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestApplicabilityNativeFixtures(t *testing.T) {
	var input struct {
		Schema string
		Cases  []struct {
			Name, Policies string
			Schema         *string
			Link           *struct {
				TemplateID          string `json:"template_id"`
				ID                  string
				Principal, Resource cedar.EntityUID
			}
		}
	}
	var expected []struct {
		Name          string
		Applicability cedar.PolicyApplicability
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/applicability/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/applicability/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input.Cases) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testRuntime(t)
	ctx := context.Background()
	for i, tc := range input.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			policies := cedar.PoliciesFromCedar(tc.Policies)
			if tc.Link != nil {
				var err error
				policies, err = rt.LinkTemplate(ctx, policies, tc.Link.TemplateID, tc.Link.ID, cedar.SlotBindings{cedar.PrincipalSlot: tc.Link.Principal, cedar.ResourceSlot: tc.Link.Resource})
				if err != nil {
					t.Fatal(err)
				}
			}
			schema := input.Schema
			if tc.Schema != nil {
				schema = *tc.Schema
			}
			got, err := rt.ApplicableEnvironments(ctx, cedar.SchemaFromCedar(schema), policies)
			if err != nil {
				t.Fatal(err)
			}
			if tc.Name != expected[i].Name || !reflect.DeepEqual(got, expected[i].Applicability) {
				t.Fatalf("Go %+v; native %+v", got, expected[i])
			}
		})
	}
}

func TestRequestEnvironmentJSONRoundTrip(t *testing.T) {
	principalSlot, resourceSlot := "A::Z", "Photo"
	want := cedar.PolicyApplicability{
		Policies: map[string][]cedar.RequestEnvironment{"policy": {{
			PrincipalType: "A::Z", Action: cedar.NewEntityUID("NS::Action", "view 雪"), ResourceType: "Photo",
			PrincipalSlotType: &principalSlot, ResourceSlotType: &resourceSlot,
		}}},
		Templates: map[string][]cedar.RequestEnvironment{},
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got cedar.PolicyApplicability
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata JSON lost identity: %s -> %+v", data, got)
	}
}

func TestRequestEnvironmentJSONRejectsInvalidUTF8(t *testing.T) {
	bad := string([]byte{0xff})
	valid := cedar.RequestEnvironment{PrincipalType: "User", Action: cedar.NewEntityUID("Action", "view"), ResourceType: "Photo"}
	for _, change := range []func(*cedar.RequestEnvironment){
		func(env *cedar.RequestEnvironment) { env.PrincipalType = bad },
		func(env *cedar.RequestEnvironment) { env.ResourceType = bad },
		func(env *cedar.RequestEnvironment) { env.Action.ID = bad },
		func(env *cedar.RequestEnvironment) { env.Action.Type = bad },
		func(env *cedar.RequestEnvironment) { env.PrincipalSlotType = &bad },
		func(env *cedar.RequestEnvironment) { env.ResourceSlotType = &bad },
	} {
		env := valid
		change(&env)
		if data, err := json.Marshal(env); err == nil || data != nil {
			t.Fatalf("metadata JSON replaced invalid UTF-8: %s %v", data, err)
		}
	}
}

func TestApplicabilityDoesNotAuthorize(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {}};`)
	policies := cedar.PoliciesFromCedar(`permit(principal, action, resource) when {principal == User::"alice"};`)
	metadata, err := rt.ApplicableEnvironments(ctx, schema, policies)
	if err != nil || len(metadata.Policies["policy0"]) != 1 {
		t.Fatalf("metadata %+v %v", metadata, err)
	}
	auth, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	response, err := auth.Authorize(ctx, cedar.Request{Principal: cedar.NewEntityUID("User", "bob"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "x")})
	if err != nil || response.Decision != cedar.Deny {
		t.Fatalf("metadata granted access: %+v %v", response, err)
	}
}

func TestApplicabilityBoundaries(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	got, err := rt.ApplicableEnvironments(ctx, cedar.SchemaFromJSON([]byte(`{}`)), cedar.PoliciesFromCedar(`permit(principal, action, resource);`))
	if err != nil || len(got.Policies["policy0"]) != 0 {
		t.Fatalf("empty schema %+v %v", got, err)
	}
	for _, tc := range []struct {
		schema   cedar.Schema
		policies cedar.PolicySet
		kind     cedar.ErrorKind
	}{
		{cedar.SchemaFromCedar("not a schema"), cedar.PolicySet{}, cedar.KindSchema},
		{cedar.SchemaFromJSON([]byte(`{}`)), cedar.PoliciesFromCedar("not a policy"), cedar.KindPolicies},
		{cedar.SchemaFromCedar(string([]byte{0xff})), cedar.PolicySet{}, cedar.KindInput},
		{cedar.SchemaFromJSON([]byte(`{}`)), cedar.PoliciesFromCedar(string([]byte{0xff})), cedar.KindInput},
	} {
		_, err := rt.ApplicableEnvironments(ctx, tc.schema, tc.policies)
		var ce *cedar.Error
		if !errors.As(err, &ce) || ce.Kind != tc.kind {
			t.Fatalf("want %s: %v", tc.kind, err)
		}
	}
}
