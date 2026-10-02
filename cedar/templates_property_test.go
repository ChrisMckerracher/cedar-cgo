package cedar_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// A linked template authorizes identically to the concrete policy produced by
// textually substituting the slot bindings, with matching policy IDs.
func TestPropertyTemplateLinkMatchesSubstitution(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		c := propGenTemplate().Draw(pt, "template")
		set, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "tmpl0", cedar.TemplateFromCedar(c.Template))
		if err != nil {
			pt.Fatalf("template rejected: %v\n%s", err, c.Template)
		}
		linked, err := rt.LinkTemplate(ctx, set, "tmpl0", c.PolicyID, c.Bindings)
		if err != nil {
			pt.Fatalf("link rejected: %v", err)
		}
		concrete := cedar.PoliciesFromCedar(c.Concrete)
		req := propGenRequest().Draw(pt, "request")
		authorize := func(policies cedar.PolicySet) cedar.Response {
			a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: policies, Entities: d.entities})
			if err != nil {
				pt.Fatalf("load: %v", err)
			}
			defer a.Close()
			resp, err := a.Authorize(ctx, req)
			if err != nil {
				pt.Fatalf("authorize: %v", err)
			}
			return resp
		}
		if fromLink, fromConcrete := authorize(linked), authorize(concrete); !propResponseEqual(fromLink, fromConcrete) {
			pt.Fatalf("linked template differs from substituted policy: %+v vs %+v\ntemplate: %s\nbindings: %v",
				fromLink, fromConcrete, c.Template, c.Bindings)
		}
	})
}

// Templates/TemplateLinks preserve IDs, slots, annotations, and bindings, and
// unlink removes exactly the linked policy while leaving the template intact.
func TestPropertyTemplateInspectionRoundtrip(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
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
