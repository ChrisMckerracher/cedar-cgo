package cedar_test

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

func TestPSTMappingNativeFixtures(t *testing.T) {
	var input []struct {
		Name, Policies string
		Entities       json.RawMessage
		Links          []struct {
			TemplateID string `json:"template_id"`
			ID         string
			Values     cedar.SlotBindings
		}
		Requests []struct {
			Principal, Action, Resource cedar.EntityUID
			Context                     json.RawMessage
		}
	}
	var expected struct {
		Version      uint32 `json:"version"`
		CedarVersion string `json:"cedar_version"`
		Cases        []struct {
			Name      string
			Policies  map[string]json.RawMessage
			Templates map[string]json.RawMessage
			Links     []struct {
				TemplateID string `json:"template_id"`
				ID         string
				Values     cedar.SlotBindings
			}
			Responses []partialFixtureResult
		}
		SpecialExpressions map[string]json.RawMessage `json:"special_expressions"`
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/pst/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/pst/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if expected.Version != cedar.ResidualProjectionVersion || expected.CedarVersion != cedar.CedarVersion || len(expected.Cases) != len(input) {
		t.Fatal("unsupported native PST fixtures")
	}
	assertSchemaJSON(t, expected.SpecialExpressions["residual_error"], []byte(`{"error":[]}`))
	assertSchemaJSON(t, expected.SpecialExpressions["unknown"], []byte(`{"unknown":[{"Value":"x"}]}`))
	assertSchemaJSON(t, expected.SpecialExpressions["slot"], []byte(`{"Slot":"?principal"}`))
	rt := testRuntime(t)
	ctx := context.Background()
	for index, test := range input {
		t.Run(test.Name, func(t *testing.T) {
			set := cedar.PoliciesFromCedar(test.Policies)
			for _, link := range test.Links {
				var err error
				set, err = rt.LinkTemplate(ctx, set, link.TemplateID, link.ID, link.Values)
				if err != nil {
					t.Fatal(err)
				}
			}
			parsed, err := rt.ParsePolicySet(ctx, set)
			if err != nil {
				t.Fatal(err)
			}
			want := expected.Cases[index]
			if len(parsed.Policies()) != len(want.Policies) {
				t.Fatal("native PST policy count differs")
			}
			for _, policy := range parsed.Policies() {
				assertSchemaJSON(t, policy.JSON(), want.Policies[policy.ID()])
			}
			templates, err := rt.Templates(ctx, set)
			if err != nil || len(templates) != len(want.Templates) {
				t.Fatalf("native PST templates: %+v %v", templates, err)
			}
			for _, template := range templates {
				assertSchemaJSON(t, template.JSON, want.Templates[template.ID])
			}
			links, err := rt.TemplateLinks(ctx, set)
			if err != nil || len(links) != len(want.Links) {
				t.Fatalf("native PST links: %+v %v", links, err)
			}
			sort.Slice(links, func(a, b int) bool { return links[a].PolicyID < links[b].PolicyID })
			for index, link := range links {
				expected := want.Links[index]
				if link.PolicyID != expected.ID || link.TemplateID != expected.TemplateID || !reflect.DeepEqual(link.Bindings, expected.Values) {
					t.Fatalf("native PST link: %+v; %+v", link, expected)
				}
			}
			for _, source := range []cedar.PolicySet{set, parsed.Source()} {
				a, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: source, Entities: cedar.EntitiesFromJSON(test.Entities)})
				if err != nil {
					t.Fatal(err)
				}
				for index, request := range test.Requests {
					response, err := a.Authorize(ctx, cedar.Request{Principal: request.Principal, Action: request.Action, Resource: request.Resource, Context: cedar.ContextFromJSON(request.Context)})
					expected := want.Responses[index]
					ids := make([]string, 0, len(response.Errors))
					for _, error := range response.Errors {
						ids = append(ids, error.PolicyID)
					}
					if err != nil || response.Decision.String() != expected.Decision || !reflect.DeepEqual(response.Reasons, expected.Reasons) || !reflect.DeepEqual(ids, expected.ErrorPolicies) {
						t.Fatalf("PST semantic roundtrip: %+v %v; %+v", response, err, expected)
					}
				}
				a.Close()
			}
		})
	}
}

func TestPropertyPSTMappedSetPreservesAuthorization(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		source := cedar.PoliciesFromCedar(propGenPolicySet(2).Draw(pt, "policies"))
		parsed, err := rt.ParsePolicySet(ctx, source)
		if err != nil {
			pt.Fatal(err)
		}
		req := propGenRequest().Draw(pt, "request")
		var responses []cedar.Response
		for _, source := range []cedar.PolicySet{source, parsed.Source()} {
			a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: source, Entities: d.entities})
			if err != nil {
				pt.Fatal(err)
			}
			response, err := a.Authorize(ctx, req)
			a.Close()
			if err != nil {
				pt.Fatal(err)
			}
			responses = append(responses, response)
		}
		if !propResponseEqual(responses[0], responses[1]) {
			pt.Fatalf("EST roundtrip changed authorization: %+v", responses)
		}
	})
}
