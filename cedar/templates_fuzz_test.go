package cedar_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

// EST form of shareTemplate from the native parity fixtures, for the JSON leg.
const fuzzTemplateJSON = `{"effect":"permit","principal":{"op":"==","slot":"?principal"},"action":{"op":"==","entity":{"id":"view","type":"Action"}},"resource":{"op":"==","slot":"?resource"},"annotations":{"description":"shared access"},"conditions":[]}`

// fuzzTemplateDecision authorizes a fixed request against set; errors must deny.
func fuzzTemplateDecision(t *testing.T, rt *cedar.Runtime, set cedar.PolicySet) (cedar.Decision, error) {
	t.Helper()
	a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Policies: set, Limits: fuzzLimits})
	if err != nil {
		checkNoFault(t, err)
		return cedar.Deny, err
	}
	defer a.Close()
	resp, err := a.Authorize(context.Background(), templateRequest())
	checkNoFault(t, err)
	if err != nil && resp.Decision != cedar.Deny {
		t.Fatalf("error %v came with %v", err, resp.Decision)
	}
	return resp.Decision, nil
}

func FuzzTemplates(f *testing.F) {
	f.Add(shareTemplate, "share", "alice-access", "User", "alice", "Photo", "beach", "")
	f.Add("", "", "", "", "", "", "", "")
	f.Add(`permit(principal, action == ?action, resource);`, "action-slot", "link", "User", "alice", "Photo", "beach", "")
	f.Add(`permit(principal == ?principal, action, resource) when { principal == ?principal };`, "cond-slot", "link", "User", "alice", "Photo", "beach", "")
	f.Add("@a(\"1\")\n@b(\"2\")\n@c(\"3\")\n@description(\"deeply annotated\")\nforbid(principal == ?principal, action, resource == ?resource);", "deep", "link", "User", "alice", "Photo", "beach", "s")
	f.Add(`permit(principal, action, resource);`, "static", "link", "User", "alice", "Photo", "beach", "")
	f.Add(shareTemplate, "share", "share", "User", "alice", "Photo", "beach", fuzzTemplateJSON)
	f.Add(shareTemplate, "t\"\\\n", "l\"雪\x00", "User", "a\n\"\\雪\x00", "Photo", "", "x")
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, source, templateID, linkID, principalType, principalID, resourceType, resourceID, opSeed string) {
		if len(source)+len(templateID)+len(linkID)+len(principalType)+len(principalID)+len(resourceType)+len(resourceID)+len(opSeed) > 8192 ||
			nesting(source) > maxFuzzNesting {
			t.Skip()
		}
		ctx := context.Background()
		if !utf8.ValidString(templateID) || !utf8.ValidString(source) {
			// Non-UTF-8 must be rejected by the Go boundary before the guest runs.
			_, err := rt.AddTemplate(ctx, cedar.PolicySet{}, templateID, cedar.TemplateFromCedar(source))
			var ce *cedar.Error
			if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
				t.Fatalf("non-UTF-8 template input: %v", err)
			}
			return
		}
		// Binding-side malformed UTF-8 must be rejected before the guest runs,
		// exactly like the template-source leg above.
		badBinding := !utf8.ValidString(linkID) || !utf8.ValidString(principalType) || !utf8.ValidString(principalID) ||
			!utf8.ValidString(resourceType) || !utf8.ValidString(resourceID)
		if badBinding || !utf8.ValidString(opSeed) {
			base := cedar.PoliciesFromCedar(`permit(principal, action, resource);`)
			set, err := rt.AddTemplate(ctx, base, "t", cedar.TemplateFromCedar(shareTemplate))
			if err != nil {
				t.Fatal(err)
			}
			if !utf8.ValidString(opSeed) {
				_, err = rt.AddTemplate(ctx, set, "t2", cedar.TemplateFromJSON([]byte(opSeed)))
				var ce *cedar.Error
				if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
					t.Fatalf("non-UTF-8 JSON template: %v", err)
				}
			}
			if badBinding {
				_, err = rt.LinkTemplate(ctx, set, "t", linkID, cedar.SlotBindings{
					cedar.PrincipalSlot: cedar.NewEntityUID(principalType, principalID),
					cedar.ResourceSlot:  cedar.NewEntityUID(resourceType, resourceID),
				})
				var ce *cedar.Error
				if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
					t.Fatalf("non-UTF-8 link input: %v", err)
				}
			}
			return
		}
		if strings.HasPrefix(opSeed, "{") {
			_, err := rt.AddTemplate(ctx, cedar.PolicySet{}, templateID, cedar.TemplateFromJSON([]byte(opSeed)))
			checkNoFault(t, err)
		}
		// The static policy keeps the pre-link decision non-trivial: linking a
		// forbid template can flip it, and unlinking must flip it back.
		base := cedar.PoliciesFromCedar(`permit(principal, action, resource);`)
		set, err := rt.AddTemplate(ctx, base, templateID, cedar.TemplateFromCedar(source))
		checkNoFault(t, err)
		if err != nil {
			return
		}
		templates, err := rt.Templates(ctx, set)
		if err != nil || len(templates) != 1 || templates[0].ID != templateID {
			t.Fatalf("successful add cannot be inspected: %v, %v", templates, err)
		}
		// A template Rust accepted must survive its own EST round trip.
		jsonSet, err := rt.AddTemplate(ctx, base, templateID, cedar.TemplateFromJSON(templates[0].JSON))
		if err != nil {
			t.Fatalf("accepted template failed its EST round trip: %v", err)
		}
		if !reflect.DeepEqual(normalizedPolicyJSON(t, []byte(set.Text())), normalizedPolicyJSON(t, []byte(jsonSet.Text()))) {
			t.Fatal("Cedar and JSON template sources produced different sets")
		}
		pre, err := fuzzTemplateDecision(t, rt, set)
		if err != nil {
			return
		}
		bindings := cedar.SlotBindings{}
		for _, slot := range templates[0].Slots {
			switch slot {
			case cedar.PrincipalSlot:
				bindings[slot] = cedar.NewEntityUID(principalType, principalID)
			case cedar.ResourceSlot:
				bindings[slot] = cedar.NewEntityUID(resourceType, resourceID)
			}
		}
		linked, err := rt.LinkTemplate(ctx, set, templateID, linkID, bindings)
		checkNoFault(t, err)
		if err != nil {
			return
		}
		links, err := rt.TemplateLinks(ctx, linked)
		if err != nil || len(links) != 1 || links[0].PolicyID != linkID || links[0].TemplateID != templateID {
			t.Fatalf("successful link not listed consistently: %v, %v", links, err)
		}
		during, err := fuzzTemplateDecision(t, rt, linked)
		if err != nil {
			return
		}
		unlinked, err := rt.UnlinkTemplate(ctx, linked, linkID)
		if err != nil {
			t.Fatalf("unlinking a listed link failed: %v", err)
		}
		if !reflect.DeepEqual(normalizedPolicyJSON(t, []byte(set.Text())), normalizedPolicyJSON(t, []byte(unlinked.Text()))) {
			t.Fatal("unlink did not restore the pre-link set")
		}
		after, err := fuzzTemplateDecision(t, rt, unlinked)
		if err != nil || after != pre {
			t.Fatalf("unlink did not restore decision %v (linked %v): %v, %v", pre, during, after, err)
		}
		if len(opSeed) > 0 && opSeed[0]%2 == 1 {
			removed, err := rt.RemoveTemplate(ctx, unlinked, templateID)
			if err != nil {
				t.Fatalf("removing an unlinked template failed: %v", err)
			}
			if empty, err := rt.Templates(ctx, removed); err != nil || len(empty) != 0 {
				t.Fatalf("template survived removal: %v, %v", empty, err)
			}
		}
	})
}
