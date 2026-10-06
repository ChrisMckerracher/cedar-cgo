package policy_test

import (
	context "context"
	json "encoding/json"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"
	partialfixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/partial"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	reflect "reflect"
	sort "sort"
	testing "testing"
)

func TestPSTMappingNativeFixtures(t *testing.T) {
	var input []struct {
		Name, Policies string
		Entities       json.RawMessage
		Links          []struct {
			TemplateID string `json:"template_id"`
			ID         string
			Values     template.SlotBindings
		}
		Requests []struct {
			Principal, Action, Resource entityuid.EntityUID
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
				Values     template.SlotBindings
			}
			Responses []partialfixture.PartialFixtureResult
		}
		SpecialExpressions map[string]json.RawMessage `json:"special_expressions"`
	}
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/pst/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/pst/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if expected.Version != cedarpartial.ResidualProjectionVersion || expected.CedarVersion != syntax.CedarVersion || len(expected.Cases) != len(input) {
		t.Fatal("unsupported native PST fixtures")
	}
	jsonassert.Equal(t, expected.SpecialExpressions["residual_error"], []byte(`{"error":[]}`))
	jsonassert.Equal(t, expected.SpecialExpressions["unknown"], []byte(`{"unknown":[{"Value":"x"}]}`))
	jsonassert.Equal(t, expected.SpecialExpressions["slot"], []byte(`{"Slot":"?principal"}`))
	rt := testruntime.New(t)
	ctx := context.Background()
	for index, test := range input {
		t.Run(test.Name, func(t *testing.T) {
			set := cedarpolicy.PoliciesFromCedar(test.Policies)
			for _, link := range test.Links {
				var err error
				set, err = rt.Templates().LinkTemplate(ctx, set, link.TemplateID, link.ID, link.Values)
				if err != nil {
					t.Fatal(err)
				}
			}
			parsed, err := rt.Policies().ParsePolicySet(ctx, set)
			if err != nil {
				t.Fatal(err)
			}
			want := expected.Cases[index]
			if len(parsed.Policies()) != len(want.Policies) {
				t.Fatal("native PST policy count differs")
			}
			for _, policy := range parsed.Policies() {
				jsonassert.Equal(t, policy.JSON(), want.Policies[policy.ID()])
			}
			templates, err := rt.Templates().Templates(ctx, set)
			if err != nil || len(templates) != len(want.Templates) {
				t.Fatalf("native PST templates: %+v %v", templates, err)
			}
			for _, template := range templates {
				jsonassert.Equal(t, template.JSON, want.Templates[template.ID])
			}
			links, err := rt.Templates().TemplateLinks(ctx, set)
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
			for _, source := range []cedarpolicy.PolicySet{set, parsed.Source()} {
				a, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: source, Entities: cedarentity.EntitiesFromJSON(test.Entities)})
				if err != nil {
					t.Fatal(err)
				}
				for index, request := range test.Requests {
					response, err := a.Authorize(ctx, cedarrequest.Request{Principal: request.Principal, Action: request.Action, Resource: request.Resource, Context: cedarrequest.ContextFromJSON(request.Context)})
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
