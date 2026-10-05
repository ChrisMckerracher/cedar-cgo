package applicability_test

import (
	context "context"
	json "encoding/json"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	applicability "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/applicability"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
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
				Principal, Resource entityuid.EntityUID
			}
		}
	}
	var expected []struct {
		Name          string
		Applicability applicability.PolicyApplicability
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/applicability/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/applicability/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input.Cases) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	for i, tc := range input.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var policies cedarpolicy.PolicySet
			if tc.Format == "json" {
				policies = cedarpolicy.PoliciesFromJSON(tc.Policies)
			} else {
				var TextValue string
				if err := json.Unmarshal(tc.Policies, &TextValue); err != nil {
					t.Fatal(err)
				}
				policies = cedarpolicy.PoliciesFromCedar(TextValue)
			}
			if tc.Link != nil {
				var err error
				policies, err = rt.Templates().LinkTemplate(ctx, policies, tc.Link.TemplateID, tc.Link.ID, template.SlotBindings{template.PrincipalSlot: tc.Link.Principal, template.ResourceSlot: tc.Link.Resource})
				if err != nil {
					t.Fatal(err)
				}
			}
			schema := input.Schema
			if tc.Schema != nil {
				schema = *tc.Schema
			}
			got, err := rt.Applicability().ApplicableEnvironments(ctx, cedarschema.SchemaFromCedar(schema), policies)
			if err != nil {
				t.Fatal(err)
			}
			if tc.Name != expected[i].Name || !reflect.DeepEqual(got, expected[i].Applicability) {
				t.Fatalf("Go %+v; native %+v", got, expected[i])
			}
			if tc.Format == "json" {
				testsupport.AssertApplicabilitySourceIDs(t, tc.Policies, got)
			}
		})
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
		Applicability applicability.PolicyApplicability
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/applicability/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/applicability/expected.json"), &expected); err != nil {
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
			testsupport.AssertApplicabilitySourceIDs(t, test.Policies, expected[i].Applicability)
			checked++
		}
	}
	if checked != 3 {
		t.Fatalf("wanted static, template, and linked raw-ID fixtures; found %d", checked)
	}
}
