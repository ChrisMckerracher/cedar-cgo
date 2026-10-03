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
			Name, Format string
			Policies     json.RawMessage
			Schema       *string
			Link         *struct {
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
			var policies cedar.PolicySet
			if tc.Format == "json" {
				policies = cedar.PoliciesFromJSON(tc.Policies)
			} else {
				var text string
				if err := json.Unmarshal(tc.Policies, &text); err != nil {
					t.Fatal(err)
				}
				policies = cedar.PoliciesFromCedar(text)
			}
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
			if tc.Format == "json" {
				assertApplicabilitySourceIDs(t, tc.Policies, got)
			}
		})
	}
}

func assertApplicabilitySourceIDs(t testing.TB, policies []byte, metadata cedar.PolicyApplicability) {
	t.Helper()
	var input struct {
		StaticPolicies map[string]json.RawMessage `json:"staticPolicies"`
		Templates      map[string]json.RawMessage
		TemplateLinks  []struct{ NewID string } `json:"templateLinks"`
	}
	if err := json.Unmarshal(policies, &input); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Policies) != len(input.StaticPolicies)+len(input.TemplateLinks) || len(metadata.Templates) != len(input.Templates) {
		t.Fatal("applicability source ID count differs")
	}
	for id := range input.StaticPolicies {
		if _, found := metadata.Policies[id]; !found {
			t.Fatalf("static source ID changed: %q", id)
		}
	}
	for id := range input.Templates {
		if _, found := metadata.Templates[id]; !found {
			t.Fatalf("template source ID changed: %q", id)
		}
	}
	for _, link := range input.TemplateLinks {
		if _, found := metadata.Policies[link.NewID]; !found {
			t.Fatalf("linked source ID changed: %q", link.NewID)
		}
	}
}

func TestApplicabilityRawIDFixtures(t *testing.T) {
	var input struct {
		Cases []struct {
			Name, Format string
			Policies     json.RawMessage
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
		t.Fatal("fixture count differs")
	}
	checked := 0
	for i, test := range input.Cases {
		if test.Format == "json" {
			if test.Name != expected[i].Name {
				t.Fatal("fixture name differs")
			}
			assertApplicabilitySourceIDs(t, test.Policies, expected[i].Applicability)
			checked++
		}
	}
	if checked != 3 {
		t.Fatalf("wanted static, template, and linked raw-ID fixtures; found %d", checked)
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
