package template_test

import (
	context "context"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	reflect "reflect"
	strings "strings"
	testing "testing"
)

func TestTemplateInspectionAndSnapshots(t *testing.T) {
	ctx, rt := context.Background(), testruntime.New(t)
	original := cedarpolicy.PoliciesFromCedar(`forbid(principal, action, resource) when { false };`)
	set, err := rt.Templates().AddTemplate(ctx, original, "share", template.TemplateFromCedar(ShareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	templates, err := rt.Templates().Templates(ctx, set)
	if err != nil || len(templates) != 1 {
		t.Fatalf("templates %v, %v", templates, err)
	}
	tmpl := templates[0]
	if tmpl.ID != "share" || !reflect.DeepEqual(tmpl.Slots, []template.SlotID{template.PrincipalSlot, template.ResourceSlot}) || tmpl.Annotations["description"] != "shared access" || !strings.Contains(tmpl.Cedar, "?principal") {
		t.Fatalf("inspection: %+v", tmpl)
	}
	jsonSource := template.TemplateFromJSON(tmpl.JSON)
	if jsonSource.Format() != syntax.FormatJSON || jsonSource.Text() != string(tmpl.JSON) {
		t.Fatal("JSON constructor lost source")
	}
	copySet, err := rt.Templates().AddTemplate(ctx, original, "share", jsonSource)
	if err != nil || !reflect.DeepEqual(NormalizedPolicyJSON(t, []byte(set.Text())), NormalizedPolicyJSON(t, []byte(copySet.Text()))) {
		t.Fatalf("JSON template round trip: %v", err)
	}
	bindings := ShareBindings()
	bindings[template.PrincipalSlot] = entityuid.NewEntityUID("User", "a\n\"\\雪\x00")
	linked, err := rt.Templates().LinkTemplate(ctx, set, "share", "link\"\n雪", bindings)
	if err != nil {
		t.Fatal(err)
	}
	links, err := rt.Templates().TemplateLinks(ctx, linked)
	if err != nil || len(links) != 1 || links[0].TemplateID != "share" || links[0].PolicyID != "link\"\n雪" || !reflect.DeepEqual(links[0].Bindings, bindings) {
		t.Fatalf("link inspection %+v, %v", links, err)
	}
	links[0].Bindings[template.PrincipalSlot] = entityuid.NewEntityUID("User", "changed")
	again, err := rt.Templates().TemplateLinks(ctx, linked)
	if err != nil || !reflect.DeepEqual(again[0].Bindings, bindings) {
		t.Fatal("inspection aliases future results")
	}
	unlinked, err := rt.Templates().UnlinkTemplate(ctx, linked, "link\"\n雪")
	if err != nil {
		t.Fatal(err)
	}
	removed, err := rt.Templates().RemoveTemplate(ctx, unlinked, "share")
	if err != nil {
		t.Fatal(err)
	}
	empty, err := rt.Templates().Templates(ctx, removed)
	if err != nil || len(empty) != 0 {
		t.Fatalf("after remove %+v, %v", empty, err)
	}
	remaining, err := rt.Templates().TemplateLinks(ctx, linked)
	if err != nil || len(remaining) != 1 {
		t.Fatal("unlink modified original snapshot")
	}
	baseTemplates, err := rt.Templates().Templates(ctx, original)
	if err != nil || len(baseTemplates) != 0 {
		t.Fatal("add modified original snapshot")
	}
}

func TestTemplateMalformedInputs(t *testing.T) {
	ctx, rt := context.Background(), testruntime.New(t)
	for _, template := range []template.Template{
		{}, template.TemplateFromCedar("nonsense"), template.TemplateFromCedar(`permit(principal, action, resource);`),
		template.TemplateFromCedar(`permit(principal, action == ?action, resource);`),
		template.TemplateFromCedar(`permit(principal, action, resource) when { principal == ?principal };`),
		template.TemplateFromJSON([]byte("{")), template.TemplateFromJSON([]byte("null")),
	} {
		if _, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "bad", template); err == nil {
			t.Fatalf("accepted malformed template %s", template.Text())
		}
	}
	set, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "share", template.TemplateFromCedar(ShareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	for _, bindings := range []template.SlotBindings{
		{"?action": entityuid.NewEntityUID("Action", "view")},
		{template.PrincipalSlot: entityuid.NewEntityUID("not a type", "alice"), template.ResourceSlot: entityuid.NewEntityUID("Photo", "beach")},
	} {
		if _, err := rt.Templates().LinkTemplate(ctx, set, "share", "bad", bindings); err == nil {
			t.Fatal("accepted invalid slot/UID")
		}
	}
	if _, err := rt.Templates().Templates(ctx, cedarpolicy.PoliciesFromJSON([]byte(`{"templates":{},"staticPolicies":{},"templateLinks":[{"templateId":"missing","newId":"bad","values":{}}]}`))); err == nil {
		t.Fatal("accepted dangling link")
	}
}
