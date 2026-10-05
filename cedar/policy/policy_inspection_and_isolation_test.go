package policy_test

import (
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
)

func TestPolicyInspectionAndIsolation(t *testing.T) {
	ctx := context.Background()
	rt := testsupport.TestRuntime(t)
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
	principal := p.PrincipalConstraint()
	if principal.Kind != cedarpolicy.ConstraintIsIn || principal.EntityType != "NS::User" || principal.Entity.ID != "admins" {
		t.Fatalf("bad principal %+v", principal)
	}
	principal.Entity.ID = "changed"
	action := p.ActionConstraint()
	if action.Kind != cedarpolicy.ConstraintIn || len(action.Entities) != 2 {
		t.Fatalf("bad action %+v", action)
	}
	action.Entities[0].ID = "changed"
	p.Annotations()["note"] = "changed"
	data := p.JSON()
	data[0] = 'X'
	syntax, _ := p.Syntax()
	syntax.Annotations["note"] = "changed"
	syntax.Conditions[0].Body[0] = 'X'
	syntax.Principal.Entity.ID = "changed"
	if p.PrincipalConstraint().Entity.ID != "admins" || p.ActionConstraint().Entities[0].ID == "changed" {
		t.Fatal("snapshot mutated through constraints")
	}
	if v, _ := p.Annotation("note"); v != "owner" {
		t.Fatal("snapshot annotations mutated")
	}
	if !json.Valid(p.JSON()) {
		t.Fatal("snapshot JSON mutated")
	}
	if _, err := rt.Policies().PolicyFromSyntax(ctx, testsupport.MustPolicySyntax(t, p)); err != nil {
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
