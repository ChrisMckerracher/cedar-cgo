package utility_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	policysupport "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/policy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	reflect "reflect"
	strings "strings"
	testing "testing"
)

func TestStandaloneValidationAndConfusables(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action "view" appliesTo { principal: User, resource: Photo, context: {count: Long} };`)
	action := entityuid.NewEntityUID("Action", "view")
	if err := cedarrequest.NewContext(cedarvalue.Record{"count": cedarvalue.Long(1)}).Validate(ctx, rt.Utilities(), schema, action); err != nil {
		t.Fatal(err)
	}
	if err := rt.Utilities().ValidateScopeVariables(ctx, schema, entityuid.NewEntityUID("User", "a"), action, entityuid.NewEntityUID("Photo", "p")); err != nil {
		t.Fatal(err)
	}
	var ce *diagnostic.Error
	if err := (cedarrequest.Context{}).Validate(ctx, rt.Utilities(), schema, action); !errors.As(err, &ce) || ce.Kind != diagnostic.KindContext {
		t.Fatalf("invalid context accepted: %v", err)
	}
	if err := rt.Utilities().ValidateScopeVariables(ctx, schema, entityuid.NewEntityUID("Photo", "a"), action, entityuid.NewEntityUID("Photo", "p")); !errors.As(err, &ce) || ce.Kind != diagnostic.KindRequest {
		t.Fatalf("invalid scope accepted: %v", err)
	}
	policies := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { "aа" == "aа" };`)
	warnings, err := rt.Utilities().ConfusableStrings(ctx, policies)
	if err != nil || len(warnings) == 0 || warnings[0].PolicyID != "policy0" || warnings[0].Category != "mixed_script_string" || warnings[0].Severity != diagnostic.SeverityWarning || len(warnings[0].Spans) == 0 {
		t.Fatalf("confusables: %+v %v", warnings, err)
	}
	version, err := rt.Utilities().LanguageVersion(ctx)
	if err != nil || version != "4.5.0" {
		t.Fatalf("language version: %q %v", version, err)
	}
	uid := entityuid.NewEntityUID("User", "\a")
	TextValue, err := uid.CedarText(ctx, rt.Utilities())
	if err != nil || TextValue == uid.String() || !strings.Contains(TextValue, `\u{7}`) {
		t.Fatalf("native escapes: %q vs %q: %v", TextValue, uid.String(), err)
	}
}

func TestConfusableMetadataAndRawPolicyIDs(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	for _, id := range []string{"", "quote\"\nslash\\\x00雪"} {
		policies := policysupport.PartialIDPolicies(t, map[string]json.RawMessage{
			id: policysupport.PartialIDPolicy("permit", "when", `{"==":{"left":{"Value":"aа"},"right":{"Value":"aа"}}}`),
		})
		warnings, err := rt.Utilities().ConfusableStrings(ctx, policies)
		if err != nil || len(warnings) == 0 {
			t.Fatalf("confusables for %q: %+v %v", id, warnings, err)
		}
		for _, warning := range warnings {
			if warning.PolicyID != id || warning.Category != "mixed_script_string" || warning.Severity != diagnostic.SeverityWarning || len(warning.Spans) != 0 {
				t.Fatalf("JSON warning %+v; want raw ID %q and no spans", warning, id)
			}
		}
	}
}

func TestNativeUtilityErrors(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	for _, TextValue := range []string{`User::"\a"`, ` User::"a"`, `User::"a";`} {
		uid, err := rt.Utilities().ParseEntityUID(ctx, TextValue)
		var ce *diagnostic.Error
		if uid != (entityuid.EntityUID{}) || !errors.As(err, &ce) || ce.Kind != diagnostic.KindEntityUID {
			t.Fatalf("invalid normalized UID %q: %+v %v", TextValue, uid, err)
		}
	}
	for _, uid := range []entityuid.EntityUID{entityuid.NewEntityUID("", "a"), entityuid.NewEntityUID("not a type", "a")} {
		TextValue, err := uid.CedarText(ctx, rt.Utilities())
		var ce *diagnostic.Error
		if TextValue != "" || !errors.As(err, &ce) || ce.Kind != diagnostic.KindEntityUID {
			t.Fatalf("invalid UID type: %q %v", TextValue, err)
		}
	}
	values, err := cedarrequest.ContextFromJSON([]byte(`[]`)).Values(ctx, rt.Utilities())
	var ce *diagnostic.Error
	if values != nil || !errors.As(err, &ce) || ce.Kind != diagnostic.KindContext {
		t.Fatalf("invalid context readback: %#v %v", values, err)
	}
	if err := (cedarrequest.Context{}).Validate(ctx, rt.Utilities(), cedarschema.SchemaFromCedar("invalid"), entityuid.NewEntityUID("Action", "view")); !errors.As(err, &ce) || ce.Kind != diagnostic.KindSchema {
		t.Fatalf("invalid schema: %v", err)
	}
	warnings, err := rt.Utilities().ConfusableStrings(ctx, cedarpolicy.PoliciesFromCedar("invalid"))
	if warnings != nil || !errors.As(err, &ce) || ce.Kind != diagnostic.KindPolicies {
		t.Fatalf("invalid policies: %+v %v", warnings, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	version, err := rt.Utilities().LanguageVersion(canceled)
	if version != "" || !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled utility operation: %q %v", version, err)
	}
}

func TestConfusableStringsDoNotDuplicateLinkedTemplates(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	policies, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "template", template.TemplateFromCedar(`permit(principal == ?principal, action, resource) when { "aа" == "aа" };`))
	if err != nil {
		t.Fatal(err)
	}
	before, err := rt.Utilities().ConfusableStrings(ctx, policies)
	if err != nil || len(before) == 0 {
		t.Fatalf("template warnings: %+v %v", before, err)
	}
	policies, err = rt.Templates().LinkTemplate(ctx, policies, "template", "link", template.SlotBindings{template.PrincipalSlot: entityuid.NewEntityUID("User", "alice")})
	if err != nil {
		t.Fatal(err)
	}
	after, err := rt.Utilities().ConfusableStrings(ctx, policies)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("link duplicated warnings: %+v -> %+v %v", before, after, err)
	}
}
