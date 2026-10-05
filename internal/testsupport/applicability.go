package testsupport

import (
	json "encoding/json"
	applicability "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/applicability"
	testing "testing"
)

func AssertApplicabilitySourceIDs(t testing.TB, policies []byte, metadata applicability.PolicyApplicability) {
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
