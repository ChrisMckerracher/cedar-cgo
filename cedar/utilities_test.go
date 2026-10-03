package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

func TestNativeUIDRoundTripProperty(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		id := rapid.StringN(0, 40, 160).Draw(pt, "id")
		typ := rapid.SampledFrom([]string{"User", "NS::User", "A::B::Photo"}).Draw(pt, "type")
		uid := cedar.NewEntityUID(typ, id)
		text, err := uid.CedarText(ctx, rt)
		if err != nil {
			pt.Fatal(err)
		}
		parsed, err := rt.ParseEntityUID(ctx, text)
		if err != nil || parsed != uid {
			pt.Fatalf("round trip %q: %+v %v", text, parsed, err)
		}
		again, err := parsed.CedarText(ctx, rt)
		if err != nil || again != text {
			pt.Fatalf("unstable text %q -> %q: %v", text, again, err)
		}
	})
}

func TestContextMergeContract(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	left := cedar.NewContext(cedar.Record{"left": cedar.Record{"a": cedar.Long(1)}})
	right := cedar.NewContext(cedar.Record{"right": cedar.Set{cedar.Bool(true), cedar.Bool(false)}, "decimal": cedar.Decimal("1.25")})
	before, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := left.Merge(ctx, rt, right)
	if err != nil {
		t.Fatal(err)
	}
	values, err := merged.Values(ctx, rt)
	if err != nil || len(values) != 3 || values["decimal"] != cedar.ExtensionValue(`decimal("1.25")`) {
		t.Fatalf("merge values: %#v %v", values, err)
	}
	if !reflect.DeepEqual(values["left"], cedar.EvalRecord{"a": cedar.Long(1)}) {
		t.Fatalf("nested value changed: %#v", values["left"])
	}
	after, err := json.Marshal(left)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("merge changed its input")
	}
	for _, other := range []cedar.Context{left, cedar.NewContext(cedar.Record{"left": cedar.Record{"b": cedar.Long(2)}})} {
		result, err := left.Merge(ctx, rt, other)
		var ce *cedar.Error
		if !errors.As(err, &ce) || ce.Kind != cedar.KindContext {
			t.Fatalf("duplicate key accepted: %+v %v", result, err)
		}
	}
	identity, err := left.Merge(ctx, rt, cedar.Context{})
	if err != nil {
		t.Fatal(err)
	}
	identityValues, err := identity.Values(ctx, rt)
	leftValues, leftErr := left.Values(ctx, rt)
	if err != nil || leftErr != nil || !reflect.DeepEqual(identityValues, leftValues) {
		t.Fatalf("empty merge changed values: %#v %#v %v %v", identityValues, leftValues, err, leftErr)
	}
}

func TestContextMergeDisjointProperty(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		a := rapid.Int64().Draw(pt, "left")
		b := rapid.StringN(0, 16, 64).Draw(pt, "right")
		left := cedar.NewContext(cedar.Record{"left": cedar.Long(a)})
		right := cedar.NewContext(cedar.Record{"right": cedar.String(b)})
		merged, err := left.Merge(ctx, rt, right)
		if err != nil {
			pt.Fatal(err)
		}
		values, err := merged.Values(ctx, rt)
		if err != nil || !reflect.DeepEqual(values, cedar.EvalRecord{"left": cedar.Long(a), "right": cedar.String(b)}) {
			pt.Fatalf("lost merged values: %#v %v", values, err)
		}
	})
}

func TestStandaloneValidationAndConfusables(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; entity Photo; action "view" appliesTo { principal: User, resource: Photo, context: {count: Long} };`)
	action := cedar.NewEntityUID("Action", "view")
	if err := cedar.NewContext(cedar.Record{"count": cedar.Long(1)}).Validate(ctx, rt, schema, action); err != nil {
		t.Fatal(err)
	}
	if err := rt.ValidateScopeVariables(ctx, schema, cedar.NewEntityUID("User", "a"), action, cedar.NewEntityUID("Photo", "p")); err != nil {
		t.Fatal(err)
	}
	var ce *cedar.Error
	if err := (cedar.Context{}).Validate(ctx, rt, schema, action); !errors.As(err, &ce) || ce.Kind != cedar.KindContext {
		t.Fatalf("invalid context accepted: %v", err)
	}
	if err := rt.ValidateScopeVariables(ctx, schema, cedar.NewEntityUID("Photo", "a"), action, cedar.NewEntityUID("Photo", "p")); !errors.As(err, &ce) || ce.Kind != cedar.KindRequest {
		t.Fatalf("invalid scope accepted: %v", err)
	}
	policies := cedar.PoliciesFromCedar(`permit(principal, action, resource) when { "aа" == "aа" };`)
	warnings, err := rt.ConfusableStrings(ctx, policies)
	if err != nil || len(warnings) == 0 || warnings[0].PolicyID != "policy0" || warnings[0].Category != "mixed_script_string" || warnings[0].Severity != cedar.SeverityWarning || len(warnings[0].Spans) == 0 {
		t.Fatalf("confusables: %+v %v", warnings, err)
	}
	version, err := rt.LanguageVersion(ctx)
	if err != nil || version != "4.5.0" {
		t.Fatalf("language version: %q %v", version, err)
	}
	uid := cedar.NewEntityUID("User", "\a")
	text, err := uid.CedarText(ctx, rt)
	if err != nil || text == uid.String() || !strings.Contains(text, `\u{7}`) {
		t.Fatalf("native escapes: %q vs %q: %v", text, uid.String(), err)
	}
}

func TestConfusableMetadataAndRawPolicyIDs(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	for _, id := range []string{"", "quote\"\nslash\\\x00雪"} {
		policies := partialIDPolicies(t, map[string]json.RawMessage{
			id: partialIDPolicy("permit", "when", `{"==":{"left":{"Value":"aа"},"right":{"Value":"aа"}}}`),
		})
		warnings, err := rt.ConfusableStrings(ctx, policies)
		if err != nil || len(warnings) == 0 {
			t.Fatalf("confusables for %q: %+v %v", id, warnings, err)
		}
		for _, warning := range warnings {
			if warning.PolicyID != id || warning.Category != "mixed_script_string" || warning.Severity != cedar.SeverityWarning || len(warning.Spans) != 0 {
				t.Fatalf("JSON warning %+v; want raw ID %q and no spans", warning, id)
			}
		}
	}
}

func TestNativeUtilityErrors(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	for _, text := range []string{`User::"\a"`, ` User::"a"`, `User::"a";`} {
		uid, err := rt.ParseEntityUID(ctx, text)
		var ce *cedar.Error
		if uid != (cedar.EntityUID{}) || !errors.As(err, &ce) || ce.Kind != cedar.KindEntityUID {
			t.Fatalf("invalid normalized UID %q: %+v %v", text, uid, err)
		}
	}
	for _, uid := range []cedar.EntityUID{cedar.NewEntityUID("", "a"), cedar.NewEntityUID("not a type", "a")} {
		text, err := uid.CedarText(ctx, rt)
		var ce *cedar.Error
		if text != "" || !errors.As(err, &ce) || ce.Kind != cedar.KindEntityUID {
			t.Fatalf("invalid UID type: %q %v", text, err)
		}
	}
	values, err := cedar.ContextFromJSON([]byte(`[]`)).Values(ctx, rt)
	var ce *cedar.Error
	if values != nil || !errors.As(err, &ce) || ce.Kind != cedar.KindContext {
		t.Fatalf("invalid context readback: %#v %v", values, err)
	}
	if err := (cedar.Context{}).Validate(ctx, rt, cedar.SchemaFromCedar("invalid"), cedar.NewEntityUID("Action", "view")); !errors.As(err, &ce) || ce.Kind != cedar.KindSchema {
		t.Fatalf("invalid schema: %v", err)
	}
	warnings, err := rt.ConfusableStrings(ctx, cedar.PoliciesFromCedar("invalid"))
	if warnings != nil || !errors.As(err, &ce) || ce.Kind != cedar.KindPolicies {
		t.Fatalf("invalid policies: %+v %v", warnings, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	version, err := rt.LanguageVersion(canceled)
	if version != "" || !errors.As(err, &ce) || ce.Kind != cedar.KindFault || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled utility operation: %q %v", version, err)
	}
}

func TestConfusableStringsDoNotDuplicateLinkedTemplates(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	policies, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "template", cedar.TemplateFromCedar(`permit(principal == ?principal, action, resource) when { "aа" == "aа" };`))
	if err != nil {
		t.Fatal(err)
	}
	before, err := rt.ConfusableStrings(ctx, policies)
	if err != nil || len(before) == 0 {
		t.Fatalf("template warnings: %+v %v", before, err)
	}
	policies, err = rt.LinkTemplate(ctx, policies, "template", "link", cedar.SlotBindings{cedar.PrincipalSlot: cedar.NewEntityUID("User", "alice")})
	if err != nil {
		t.Fatal(err)
	}
	after, err := rt.ConfusableStrings(ctx, policies)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("link duplicated warnings: %+v -> %+v %v", before, after, err)
	}
}

func FuzzNativeUIDRoundTrip(f *testing.F) {
	rt := testRuntime(f)
	for _, id := range []string{"", "雪😀", "\x00\a\b\f\n\r\t\"\\", "plain", string([]byte{0xff})} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if len(id) > 4096 {
			t.Skip()
		}
		uid := cedar.NewEntityUID("NS::User", id)
		text, err := uid.CedarText(context.Background(), rt)
		if !utf8.ValidString(id) {
			var ce *cedar.Error
			if text != "" || !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
				t.Fatalf("accepted invalid UTF-8: %q %v", text, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := rt.ParseEntityUID(context.Background(), text)
		if err != nil || parsed != uid {
			t.Fatalf("round trip %q: %+v %v", text, parsed, err)
		}
	})
}
