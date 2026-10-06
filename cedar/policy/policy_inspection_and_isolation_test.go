package policy_test

import (
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	policysupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/policy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func TestPolicyInspectionAndIsolation(t *testing.T) {
	ctx := context.Background()
	rt := testruntime.New(t)
	p, err := rt.Policies().ParsePolicy(ctx, "my-id", `@note("owner") @empty permit(principal is NS::User in NS::Group::"admins", action in [Action::"view", Action::"edit"], resource == Photo::"one") when { 9223372036854775807 == 9223372036854775807 } unless { false };`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Effect() != cedarpolicy.Permit || !p.HasNonScopeConstraint() || !p.IsStatic() {
		t.Fatal("incorrect metadata")
	}
	if v, ok := p.Annotation("empty"); !ok || v != "" {
		t.Fatal("lost empty annotation")
	}
	if _, ok := p.Annotation("missing"); ok {
		t.Fatal("unexpected annotation")
	}
	document := policysupport.MustPolicyJSON(t, p)
	principal := document["principal"].(map[string]any)
	if principal["op"] != "is" || principal["entity_type"] != "NS::User" || principal["in"].(map[string]any)["entity"].(map[string]any)["id"] != "admins" {
		t.Fatalf("bad principal %+v", principal)
	}
	principal["in"].(map[string]any)["entity"].(map[string]any)["id"] = "changed"
	action := document["action"].(map[string]any)
	if action["op"] != "in" || len(action["entities"].([]any)) != 2 {
		t.Fatalf("bad action %+v", action)
	}
	action["entities"].([]any)[0].(map[string]any)["id"] = "changed"
	p.Annotations()["note"] = "changed"
	data := p.JSON()
	data[0] = 'X'
	document["annotations"].(map[string]any)["note"] = "changed"
	document["conditions"].([]any)[0].(map[string]any)["body"] = json.RawMessage(`{`)
	unchanged := policysupport.MustPolicyJSON(t, p)
	if unchanged["principal"].(map[string]any)["in"].(map[string]any)["entity"].(map[string]any)["id"] != "admins" || unchanged["action"].(map[string]any)["entities"].([]any)[0].(map[string]any)["id"] == "changed" {
		t.Fatal("snapshot mutated through constraints")
	}
	if v, _ := p.Annotation("note"); v != "owner" {
		t.Fatal("snapshot annotations mutated")
	}
	if !json.Valid(p.JSON()) {
		t.Fatal("snapshot JSON mutated")
	}
	if _, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON()); err != nil {
		t.Fatal(err)
	}
	set, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar(""), p)
	if err != nil {
		t.Fatal(err)
	}
	list := set.Policies()
	list[0] = cedarpolicy.ParsedPolicy{}
	if q, ok := set.Policy("my-id"); !ok || q.ID() != "my-id" {
		t.Fatal("set mutated")
	}
	TextValue, err := set.Cedar()
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromCedar(TextValue))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rendered.Policy("policy0"); !ok {
		t.Fatal("Cedar did not assign default ID")
	}
	if _, ok := rendered.Policy("my-id"); ok {
		t.Fatal("Cedar unexpectedly retained ID")
	}
}
