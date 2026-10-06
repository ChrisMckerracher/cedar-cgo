package template_test

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	reflect "reflect"
	strings "strings"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzTemplates(f *testing.F) {
	f.Add(ShareTemplate, "share", "alice-access", "User", "alice", "Photo", "beach", "")
	f.Add("", "", "", "", "", "", "", "")
	f.Add(`permit(principal, action == ?action, resource);`, "action-slot", "link", "User", "alice", "Photo", "beach", "")
	f.Add(`permit(principal == ?principal, action, resource) when { principal == ?principal };`, "cond-slot", "link", "User", "alice", "Photo", "beach", "")
	f.Add("@a(\"1\")\n@b(\"2\")\n@c(\"3\")\n@description(\"deeply annotated\")\nforbid(principal == ?principal, action, resource == ?resource);", "deep", "link", "User", "alice", "Photo", "beach", "s")
	f.Add(`permit(principal, action, resource);`, "static", "link", "User", "alice", "Photo", "beach", "")
	f.Add(ShareTemplate, "share", "share", "User", "alice", "Photo", "beach", FuzzTemplateJSON)
	f.Add(ShareTemplate, "t\"\\\n", "l\"雪\x00", "User", "a\n\"\\雪\x00", "Photo", "", "x")
	rt := testruntime.New(f)
	f.Fuzz(func(t *testing.T, source, templateID, linkID, principalType, principalID, resourceType, resourceID, opSeed string) {
		if len(source)+len(templateID)+len(linkID)+len(principalType)+len(principalID)+len(resourceType)+len(resourceID)+len(opSeed) > 8192 ||
			fuzz.Nesting(source) > fuzz.MaxFuzzNesting {
			t.Skip()
		}
		ctx := context.Background()
		if !utf8.ValidString(templateID) || !utf8.ValidString(source) {
			// Non-UTF-8 must be rejected by the Go boundary before native execution.
			_, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, templateID, template.TemplateFromCedar(source))
			var ce *diagnostic.Error
			if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
				t.Fatalf("non-UTF-8 template input: %v", err)
			}
			return
		}
		// Binding-side malformed UTF-8 must be rejected before native execution,
		// exactly like the template-source leg above.
		badBinding := !utf8.ValidString(linkID) || !utf8.ValidString(principalType) || !utf8.ValidString(principalID) ||
			!utf8.ValidString(resourceType) || !utf8.ValidString(resourceID)
		if badBinding || !utf8.ValidString(opSeed) {
			base := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource);`)
			set, err := rt.Templates().AddTemplate(ctx, base, "t", template.TemplateFromCedar(ShareTemplate))
			if err != nil {
				t.Fatal(err)
			}
			if !utf8.ValidString(opSeed) {
				_, err = rt.Templates().AddTemplate(ctx, set, "t2", template.TemplateFromJSON([]byte(opSeed)))
				var ce *diagnostic.Error
				if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
					t.Fatalf("non-UTF-8 JSON template: %v", err)
				}
			}
			if badBinding {
				_, err = rt.Templates().LinkTemplate(ctx, set, "t", linkID, template.SlotBindings{
					template.PrincipalSlot: entityuid.NewEntityUID(principalType, principalID),
					template.ResourceSlot:  entityuid.NewEntityUID(resourceType, resourceID),
				})
				var ce *diagnostic.Error
				if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
					t.Fatalf("non-UTF-8 link input: %v", err)
				}
			}
			return
		}
		if strings.HasPrefix(opSeed, "{") {
			_, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, templateID, template.TemplateFromJSON([]byte(opSeed)))
			fault.CheckNoFault(t, err)
		}
		// The static policy keeps the pre-link decision non-trivial: linking a
		// forbid template can flip it, and unlinking must flip it back.
		base := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource);`)
		set, err := rt.Templates().AddTemplate(ctx, base, templateID, template.TemplateFromCedar(source))
		fault.CheckNoFault(t, err)
		if err != nil {
			return
		}
		templates, err := rt.Templates().Templates(ctx, set)
		if err != nil || len(templates) != 1 || templates[0].ID != templateID {
			t.Fatalf("successful add cannot be inspected: %v, %v", templates, err)
		}
		// A template Rust accepted must survive its own EST round trip.
		jsonSet, err := rt.Templates().AddTemplate(ctx, base, templateID, template.TemplateFromJSON(templates[0].JSON))
		if err != nil {
			t.Fatalf("accepted template failed its EST round trip: %v", err)
		}
		if !reflect.DeepEqual(NormalizedPolicyJSON(t, []byte(set.Text())), NormalizedPolicyJSON(t, []byte(jsonSet.Text()))) {
			t.Fatal("Cedar and JSON template sources produced different sets")
		}
		pre, err := fuzzTemplateDecision(t, rt, set)
		if err != nil {
			return
		}
		bindings := template.SlotBindings{}
		for _, slot := range templates[0].Slots {
			switch slot {
			case template.PrincipalSlot:
				bindings[slot] = entityuid.NewEntityUID(principalType, principalID)
			case template.ResourceSlot:
				bindings[slot] = entityuid.NewEntityUID(resourceType, resourceID)
			}
		}
		linked, err := rt.Templates().LinkTemplate(ctx, set, templateID, linkID, bindings)
		fault.CheckNoFault(t, err)
		if err != nil {
			return
		}
		links, err := rt.Templates().TemplateLinks(ctx, linked)
		if err != nil || len(links) != 1 || links[0].PolicyID != linkID || links[0].TemplateID != templateID {
			t.Fatalf("successful link not listed consistently: %v, %v", links, err)
		}
		during, err := fuzzTemplateDecision(t, rt, linked)
		if err != nil {
			return
		}
		unlinked, err := rt.Templates().UnlinkTemplate(ctx, linked, linkID)
		if err != nil {
			t.Fatalf("unlinking a listed link failed: %v", err)
		}
		if !reflect.DeepEqual(NormalizedPolicyJSON(t, []byte(set.Text())), NormalizedPolicyJSON(t, []byte(unlinked.Text()))) {
			t.Fatal("unlink did not restore the pre-link set")
		}
		after, err := fuzzTemplateDecision(t, rt, unlinked)
		if err != nil || after != pre {
			t.Fatalf("unlink did not restore decision %v (linked %v): %v, %v", pre, during, after, err)
		}
		if len(opSeed) > 0 && opSeed[0]%2 == 1 {
			removed, err := rt.Templates().RemoveTemplate(ctx, unlinked, templateID)
			if err != nil {
				t.Fatalf("removing an unlinked template failed: %v", err)
			}
			if empty, err := rt.Templates().Templates(ctx, removed); err != nil || len(empty) != 0 {
				t.Fatalf("template survived removal: %v, %v", empty, err)
			}
		}
	})
}
