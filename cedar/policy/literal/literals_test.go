package literal_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	reflect "reflect"
	strings "strings"
	testing "testing"
)

func TestSimultaneousEntityLiteralSubstitution(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	a, b, c := entityuid.NewEntityUID("User", "A"), entityuid.NewEntityUID("User", "B"), entityuid.NewEntityUID("User", "C")
	source := cedarpolicy.PoliciesFromCedar(`@note("雪") permit(principal == User::"A", action, resource) when { resource == User::"B" && "User::\"A\"" == "User::\"A\"" };`)
	inventory, err := rt.PolicyLiterals().EntityLiterals(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory.Policies["policy0"], []entityuid.EntityUID{a, b}) {
		t.Fatalf("inventory %+v", inventory)
	}
	changed, err := rt.PolicyLiterals().SubstituteEntityLiterals(ctx, source, map[entityuid.EntityUID]entityuid.EntityUID{a: b, b: c})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err = rt.PolicyLiterals().EntityLiterals(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory.Policies["policy0"], []entityuid.EntityUID{b, c}) {
		t.Fatalf("substitution cascaded: %+v", inventory)
	}
	if !strings.Contains(changed.Text(), `User::\"A\"`) {
		t.Fatal("string literal changed")
	}
	parsed, err := rt.Policies().ParsePolicySet(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := parsed.Policy("policy0")
	if !ok || policy.Annotations()["note"] != "雪" {
		t.Fatal("policy identity or annotation changed")
	}
	authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: changed})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedarrequest.Request{Principal: b, Action: entityuid.NewEntityUID("Action", "view"), Resource: c})
	if err != nil || response.Decision != cedarrequest.Allow {
		t.Fatalf("transformed request: %+v %v", response, err)
	}
}

func TestTemplateEntityLiteralSubstitution(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	a, b := entityuid.NewEntityUID("User", "A"), entityuid.NewEntityUID("User", "B")
	source, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "template", template.TemplateFromCedar(`@note("雪") permit(principal == ?principal, action, resource == User::"A");`))
	if err != nil {
		t.Fatal(err)
	}
	source, err = rt.Templates().LinkTemplate(ctx, source, "template", "link", template.SlotBindings{template.PrincipalSlot: a})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := rt.PolicyLiterals().SubstituteEntityLiterals(ctx, source, map[entityuid.EntityUID]entityuid.EntityUID{a: b})
	if err != nil {
		t.Fatal(err)
	}
	templates, err := rt.Templates().Templates(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 1 || templates[0].ID != "template" || templates[0].Annotations["note"] != "雪" || !reflect.DeepEqual(templates[0].Slots, []template.SlotID{template.PrincipalSlot}) {
		t.Fatalf("template identity changed: %+v", templates)
	}
	links, err := rt.Templates().TemplateLinks(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].PolicyID != "link" || links[0].TemplateID != "template" || links[0].Bindings[template.PrincipalSlot] != b {
		t.Fatalf("link identity or bindings: %+v", links)
	}
	inventory, err := rt.PolicyLiterals().EntityLiterals(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory.Templates["template"], []entityuid.EntityUID{b}) {
		t.Fatalf("template literals: %+v", inventory)
	}
	authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: changed})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedarrequest.Request{Principal: b, Action: entityuid.NewEntityUID("Action", "view"), Resource: b})
	if err != nil || response.Decision != cedarrequest.Allow {
		t.Fatalf("transformed template request: %+v %v", response, err)
	}
}
