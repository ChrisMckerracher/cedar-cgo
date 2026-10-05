package template_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	rapid "pgregory.net/rapid"
	reflect "reflect"
	testing "testing"
)

// A linked template authorizes identically to the concrete policy produced by
// textually substituting the slot bindings, with matching policy IDs.
func TestPropertyTemplateLinkMatchesSubstitution(t *testing.T) {
	d := testsupport.LoadJoy(t)
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		c := generator.PropGenTemplate().Draw(pt, "template")
		set, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "tmpl0", template.TemplateFromCedar(c.Template))
		if err != nil {
			pt.Fatalf("template rejected: %v\n%s", err, c.Template)
		}
		linked, err := rt.Templates().LinkTemplate(ctx, set, "tmpl0", c.PolicyID, c.Bindings)
		if err != nil {
			pt.Fatalf("link rejected: %v", err)
		}
		policy, err := rt.Policies().ParsePolicy(ctx, c.PolicyID, c.Concrete)
		if err != nil {
			pt.Fatalf("concrete policy rejected: %v", err)
		}
		concrete, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PolicySet{}, policy)
		if err != nil {
			pt.Fatalf("concrete policy set rejected: %v", err)
		}
		req := generator.PropGenRequest().Draw(pt, "request")
		load := func(policies cedarpolicy.PolicySet) *authorization.Authorizer {
			a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &d.Schema, Policies: policies, Entities: d.Entities})
			if err != nil {
				pt.Fatalf("load: %v", err)
			}
			return a
		}
		fromLink := load(linked)
		defer fromLink.Close()
		fromConcrete := load(concrete.Source())
		defer fromConcrete.Close()
		authorize := func(a *authorization.Authorizer, request cedarrequest.Request) cedarrequest.Response {
			resp, err := a.Authorize(ctx, request)
			if err != nil {
				pt.Fatalf("authorize: %v", err)
			}
			return resp
		}
		requests := []cedarrequest.Request{req}
		req.Principal = c.Bindings[template.PrincipalSlot]
		req.Resource = c.Bindings[template.ResourceSlot]
		// Matching bindings and each valid action exercise applicable template scopes.
		for _, action := range generator.PropJoyActions {
			req.Action = entityuid.NewEntityUID("Joy::Action", action)
			requests = append(requests, req)
		}
		for _, request := range requests {
			if linkedResponse, concreteResponse := authorize(fromLink, request), authorize(fromConcrete, request); !generator.PropResponseEqual(linkedResponse, concreteResponse) {
				pt.Fatalf("linked template differs from substituted policy: %+v vs %+v\ntemplate: %s\nbindings: %v\nrequest: %+v",
					linkedResponse, concreteResponse, c.Template, c.Bindings, request)
			}
		}
	})
}

// Templates/TemplateLinks preserve IDs, slots, annotations, and bindings, and
// unlink removes exactly the linked policy while leaving the template intact.
func TestPropertyTemplateInspectionRoundtrip(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		c := generator.PropGenTemplate().Draw(pt, "template")
		base, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "tmpl0", template.TemplateFromCedar(c.Template))
		if err != nil {
			pt.Fatalf("template rejected: %v\n%s", err, c.Template)
		}
		templates, err := rt.Templates().Templates(ctx, base)
		if err != nil || len(templates) != 1 {
			pt.Fatalf("templates: %v, %v", templates, err)
		}
		info := templates[0]
		if info.ID != "tmpl0" || !reflect.DeepEqual(info.Slots, []template.SlotID{template.PrincipalSlot, template.ResourceSlot}) {
			pt.Fatalf("inspection lost ID or slots: %+v", info)
		}
		if info.Annotations["description"] != c.Description {
			pt.Fatalf("inspection lost annotations: %v vs %q", info.Annotations, c.Description)
		}
		linked, err := rt.Templates().LinkTemplate(ctx, base, "tmpl0", c.PolicyID, c.Bindings)
		if err != nil {
			pt.Fatalf("link rejected: %v", err)
		}
		links, err := rt.Templates().TemplateLinks(ctx, linked)
		if err != nil || len(links) != 1 || links[0].PolicyID != c.PolicyID || links[0].TemplateID != "tmpl0" ||
			!reflect.DeepEqual(links[0].Bindings, c.Bindings) {
			pt.Fatalf("link inspection: %+v, %v", links, err)
		}
		unlinked, err := rt.Templates().UnlinkTemplate(ctx, linked, c.PolicyID)
		if err != nil {
			pt.Fatalf("unlink rejected: %v", err)
		}
		if links, err = rt.Templates().TemplateLinks(ctx, unlinked); err != nil || len(links) != 0 {
			pt.Fatalf("unlink left links behind: %+v, %v", links, err)
		}
		if templates, err = rt.Templates().Templates(ctx, unlinked); err != nil || len(templates) != 1 || templates[0].ID != "tmpl0" {
			pt.Fatalf("unlink removed the template: %+v, %v", templates, err)
		}
		if !reflect.DeepEqual(generator.PropNormalizedPolicyJSON(pt, []byte(base.Text())), generator.PropNormalizedPolicyJSON(pt, []byte(unlinked.Text()))) {
			pt.Fatalf("unlink did not restore the pre-link set:\n%s\n%s", base.Text(), unlinked.Text())
		}
	})
}
