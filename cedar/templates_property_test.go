package cedar_test

import (
	"context"
	"reflect"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// A linked template authorizes identically to the concrete policy produced by
// textually substituting the slot bindings, with matching policy IDs.
func TestPropertyTemplateLinkMatchesSubstitution(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		c := propGenTemplate().Draw(pt, "template")
		set, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "tmpl0", cedar.TemplateFromCedar(c.Template))
		if err != nil {
			pt.Fatalf("template rejected: %v\n%s", err, c.Template)
		}
		linked, err := rt.LinkTemplate(ctx, set, "tmpl0", c.PolicyID, c.Bindings)
		if err != nil {
			pt.Fatalf("link rejected: %v", err)
		}
		policy, err := rt.ParsePolicy(ctx, c.PolicyID, c.Concrete)
		if err != nil {
			pt.Fatalf("concrete policy rejected: %v", err)
		}
		concrete, err := rt.AddPolicy(ctx, cedar.PolicySet{}, policy)
		if err != nil {
			pt.Fatalf("concrete policy set rejected: %v", err)
		}
		req := propGenRequest().Draw(pt, "request")
		load := func(policies cedar.PolicySet) *cedar.Authorizer {
			a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: policies, Entities: d.entities})
			if err != nil {
				pt.Fatalf("load: %v", err)
			}
			return a
		}
		fromLink := load(linked)
		defer fromLink.Close()
		fromConcrete := load(concrete.Source())
		defer fromConcrete.Close()
		authorize := func(a *cedar.Authorizer, request cedar.Request) cedar.Response {
			resp, err := a.Authorize(ctx, request)
			if err != nil {
				pt.Fatalf("authorize: %v", err)
			}
			return resp
		}
		requests := []cedar.Request{req}
		req.Principal = c.Bindings[cedar.PrincipalSlot]
		req.Resource = c.Bindings[cedar.ResourceSlot]
		// Matching bindings and each valid action exercise applicable template scopes.
		for _, action := range propJoyActions {
			req.Action = cedar.NewEntityUID("Joy::Action", action)
			requests = append(requests, req)
		}
		for _, request := range requests {
			if linkedResponse, concreteResponse := authorize(fromLink, request), authorize(fromConcrete, request); !propResponseEqual(linkedResponse, concreteResponse) {
				pt.Fatalf("linked template differs from substituted policy: %+v vs %+v\ntemplate: %s\nbindings: %v\nrequest: %+v",
					linkedResponse, concreteResponse, c.Template, c.Bindings, request)
			}
		}
	})
}

// Templates/TemplateLinks preserve IDs, slots, annotations, and bindings, and
// unlink removes exactly the linked policy while leaving the template intact.
func TestPropertyTemplateInspectionRoundtrip(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		c := propGenTemplate().Draw(pt, "template")
		base, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "tmpl0", cedar.TemplateFromCedar(c.Template))
		if err != nil {
			pt.Fatalf("template rejected: %v\n%s", err, c.Template)
		}
		templates, err := rt.Templates(ctx, base)
		if err != nil || len(templates) != 1 {
			pt.Fatalf("templates: %v, %v", templates, err)
		}
		info := templates[0]
		if info.ID != "tmpl0" || !reflect.DeepEqual(info.Slots, []cedar.SlotID{cedar.PrincipalSlot, cedar.ResourceSlot}) {
			pt.Fatalf("inspection lost ID or slots: %+v", info)
		}
		if info.Annotations["description"] != c.Description {
			pt.Fatalf("inspection lost annotations: %v vs %q", info.Annotations, c.Description)
		}
		linked, err := rt.LinkTemplate(ctx, base, "tmpl0", c.PolicyID, c.Bindings)
		if err != nil {
			pt.Fatalf("link rejected: %v", err)
		}
		links, err := rt.TemplateLinks(ctx, linked)
		if err != nil || len(links) != 1 || links[0].PolicyID != c.PolicyID || links[0].TemplateID != "tmpl0" ||
			!reflect.DeepEqual(links[0].Bindings, c.Bindings) {
			pt.Fatalf("link inspection: %+v, %v", links, err)
		}
		unlinked, err := rt.UnlinkTemplate(ctx, linked, c.PolicyID)
		if err != nil {
			pt.Fatalf("unlink rejected: %v", err)
		}
		if links, err = rt.TemplateLinks(ctx, unlinked); err != nil || len(links) != 0 {
			pt.Fatalf("unlink left links behind: %+v, %v", links, err)
		}
		if templates, err = rt.Templates(ctx, unlinked); err != nil || len(templates) != 1 || templates[0].ID != "tmpl0" {
			pt.Fatalf("unlink removed the template: %+v, %v", templates, err)
		}
		if !reflect.DeepEqual(propNormalizedPolicyJSON(pt, []byte(base.Text())), propNormalizedPolicyJSON(pt, []byte(unlinked.Text()))) {
			pt.Fatalf("unlink did not restore the pre-link set:\n%s\n%s", base.Text(), unlinked.Text())
		}
	})
}
