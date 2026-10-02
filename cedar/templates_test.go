package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

const shareTemplate = `@description("shared access") permit(principal == ?principal, action == Action::"view", resource == ?resource);`
const templateSchema = `entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {} };`

func shareBindings() cedar.SlotBindings {
	return cedar.SlotBindings{
		cedar.PrincipalSlot: cedar.NewEntityUID("User", "alice"),
		cedar.ResourceSlot:  cedar.NewEntityUID("Photo", "beach"),
	}
}

func templateRequest() cedar.Request {
	return cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "beach")}
}

func TestTemplateNativeParity(t *testing.T) {
	var fixtures struct {
		CedarVersion string `json:"cedar_version"`
		Schema       string
		Cases        []struct {
			Name      string
			Policies  json.RawMessage
			Operation struct {
				Op         string
				ID         string
				TemplateID string `json:"template_id"`
				PolicyID   string `json:"policy_id"`
				Template   string
				Bindings   map[cedar.SlotID]struct{ Type, ID string }
			}
			Expected struct {
				Error    string
				Policies json.RawMessage
				Decision string
				Reasons  []string
				Valid    bool
				Errors   []cedar.PolicyMessage
				Warnings []cedar.PolicyMessage
			}
		}
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/templates/native.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.CedarVersion != "4.13.0" || len(fixtures.Cases) < 20 {
		t.Fatal("missing pinned native template fixtures")
	}
	ctx, rt := context.Background(), testRuntime(t)
	for _, tc := range fixtures.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			before := cedar.PoliciesFromJSON(tc.Policies)
			op := tc.Operation
			var got cedar.PolicySet
			var err error
			switch op.Op {
			case "add":
				got, err = rt.AddTemplate(ctx, before, op.ID, cedar.TemplateFromCedar(op.Template))
			case "link":
				bindings := make(cedar.SlotBindings)
				for slot, uid := range op.Bindings {
					bindings[slot] = cedar.NewEntityUID(uid.Type, uid.ID)
				}
				got, err = rt.LinkTemplate(ctx, before, op.TemplateID, op.PolicyID, bindings)
			case "unlink":
				got, err = rt.UnlinkTemplate(ctx, before, op.PolicyID)
			case "remove":
				got, err = rt.RemoveTemplate(ctx, before, op.TemplateID)
			default:
				t.Fatalf("unknown fixture operation %q", op.Op)
			}
			if tc.Expected.Error != "" {
				var ce *cedar.Error
				if !errors.As(err, &ce) || ce.Kind != cedar.KindPolicies || ce.Message != tc.Expected.Error {
					t.Fatalf("got %v; native Rust error: %s", err, tc.Expected.Error)
				}
				if got.Text() != "" || before.Text() != string(tc.Policies) {
					t.Fatal("failed operation returned a result or changed the source")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normalizedPolicyJSON(t, []byte(got.Text())), normalizedPolicyJSON(t, tc.Expected.Policies)) {
				t.Fatalf("Go result %s differs from native Rust %s", got.Text(), tc.Expected.Policies)
			}
			schema := cedar.SchemaFromCedar(fixtures.Schema)
			validation, err := rt.Validate(ctx, schema, got)
			if err != nil || validation.Passed != tc.Expected.Valid || !equalTemplateMessages(validation.Errors, tc.Expected.Errors) || !equalTemplateMessages(validation.Warnings, tc.Expected.Warnings) {
				t.Fatalf("validation %+v, %v; native passed=%v", validation, err, tc.Expected.Valid)
			}
			a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: got})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			response, err := a.Authorize(ctx, templateRequest())
			if err != nil || response.Decision.String() != tc.Expected.Decision || !reflect.DeepEqual(response.Reasons, tc.Expected.Reasons) || len(response.Errors) != 0 {
				t.Fatalf("authorization %+v, %v; native %s %v", response, err, tc.Expected.Decision, tc.Expected.Reasons)
			}
		})
	}
}

func normalizedPolicyJSON(t testing.TB, data []byte) any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if links, ok := value["templateLinks"].([]any); ok {
		sort.Slice(links, func(i, j int) bool {
			a, _ := json.Marshal(links[i])
			b, _ := json.Marshal(links[j])
			return string(a) < string(b)
		})
	}
	return value
}

func TestTemplateExactIntegerPreservation(t *testing.T) {
	want := map[string]string{
		"float-boundary": "9007199254740992",
		"above-float":    "9007199254740993",
		"maximum":        "9223372036854775807",
		"minimum":        "-9223372036854775808",
	}
	policies := make(map[string]json.RawMessage, len(want))
	for id, literal := range want {
		policies[id] = json.RawMessage(`{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"==":{"left":{"Value":` + literal + `},"right":{"Value":` + literal + `}}}}]}`)
	}
	data, err := json.Marshal(map[string]any{"staticPolicies": policies, "templates": map[string]any{}, "templateLinks": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	original := cedar.PoliciesFromJSON(data)
	check := func(set cedar.PolicySet) {
		t.Helper()
		var output struct {
			StaticPolicies map[string]struct {
				Conditions []struct {
					Body map[string]map[string]struct{ Value json.Number }
				}
			}
		}
		if err := json.Unmarshal([]byte(set.Text()), &output); err != nil {
			t.Fatal(err)
		}
		if len(output.StaticPolicies) != len(want) {
			t.Fatal("static policies changed during template editing")
		}
		for id, literal := range want {
			policy, ok := output.StaticPolicies[id]
			if !ok || len(policy.Conditions) != 1 {
				t.Fatalf("missing static policy condition for %q", id)
			}
			// Compare exact JSON number tokens, independently of normalizedPolicyJSON.
			for _, side := range []string{"left", "right"} {
				if got := policy.Conditions[0].Body["=="][side].Value.String(); got != literal {
					t.Fatalf("%s %s literal changed: %s, want %s", id, side, got, literal)
				}
			}
		}
	}
	ctx, rt := context.Background(), testRuntime(t)
	set, err := rt.AddTemplate(ctx, original, "share", cedar.TemplateFromCedar(shareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	set, err = rt.LinkTemplate(ctx, set, "share", "linked", shareBindings())
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	set, err = rt.UnlinkTemplate(ctx, set, "linked")
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	set, err = rt.RemoveTemplate(ctx, set, "share")
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	if !reflect.DeepEqual(normalizedPolicyJSON(t, []byte(original.Text())), normalizedPolicyJSON(t, []byte(set.Text()))) {
		t.Fatalf("template round trip changed the original policy set:\noriginal %s\nresult %s", original.Text(), set.Text())
	}
}

func TestTemplateInspectionAndSnapshots(t *testing.T) {
	ctx, rt := context.Background(), testRuntime(t)
	original := cedar.PoliciesFromCedar(`forbid(principal, action, resource) when { false };`)
	set, err := rt.AddTemplate(ctx, original, "share", cedar.TemplateFromCedar(shareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	templates, err := rt.Templates(ctx, set)
	if err != nil || len(templates) != 1 {
		t.Fatalf("templates %v, %v", templates, err)
	}
	tmpl := templates[0]
	if tmpl.ID != "share" || !reflect.DeepEqual(tmpl.Slots, []cedar.SlotID{cedar.PrincipalSlot, cedar.ResourceSlot}) || tmpl.Annotations["description"] != "shared access" || !strings.Contains(tmpl.Cedar, "?principal") {
		t.Fatalf("inspection: %+v", tmpl)
	}
	jsonSource := cedar.TemplateFromJSON(tmpl.JSON)
	if jsonSource.Format() != cedar.FormatJSON || jsonSource.Text() != string(tmpl.JSON) {
		t.Fatal("JSON constructor lost source")
	}
	copySet, err := rt.AddTemplate(ctx, original, "share", jsonSource)
	if err != nil || !reflect.DeepEqual(normalizedPolicyJSON(t, []byte(set.Text())), normalizedPolicyJSON(t, []byte(copySet.Text()))) {
		t.Fatalf("JSON template round trip: %v", err)
	}
	bindings := shareBindings()
	bindings[cedar.PrincipalSlot] = cedar.NewEntityUID("User", "a\n\"\\雪\x00")
	linked, err := rt.LinkTemplate(ctx, set, "share", "link\"\n雪", bindings)
	if err != nil {
		t.Fatal(err)
	}
	links, err := rt.TemplateLinks(ctx, linked)
	if err != nil || len(links) != 1 || links[0].TemplateID != "share" || links[0].PolicyID != "link\"\n雪" || !reflect.DeepEqual(links[0].Bindings, bindings) {
		t.Fatalf("link inspection %+v, %v", links, err)
	}
	links[0].Bindings[cedar.PrincipalSlot] = cedar.NewEntityUID("User", "changed")
	again, err := rt.TemplateLinks(ctx, linked)
	if err != nil || !reflect.DeepEqual(again[0].Bindings, bindings) {
		t.Fatal("inspection aliases future results")
	}
	unlinked, err := rt.UnlinkTemplate(ctx, linked, "link\"\n雪")
	if err != nil {
		t.Fatal(err)
	}
	removed, err := rt.RemoveTemplate(ctx, unlinked, "share")
	if err != nil {
		t.Fatal(err)
	}
	empty, err := rt.Templates(ctx, removed)
	if err != nil || len(empty) != 0 {
		t.Fatalf("after remove %+v, %v", empty, err)
	}
	remaining, err := rt.TemplateLinks(ctx, linked)
	if err != nil || len(remaining) != 1 {
		t.Fatal("unlink modified original snapshot")
	}
	baseTemplates, err := rt.Templates(ctx, original)
	if err != nil || len(baseTemplates) != 0 {
		t.Fatal("add modified original snapshot")
	}
}

func TestTemplateMalformedInputs(t *testing.T) {
	ctx, rt := context.Background(), testRuntime(t)
	for _, template := range []cedar.Template{
		{}, cedar.TemplateFromCedar("nonsense"), cedar.TemplateFromCedar(`permit(principal, action, resource);`),
		cedar.TemplateFromCedar(`permit(principal, action == ?action, resource);`),
		cedar.TemplateFromCedar(`permit(principal, action, resource) when { principal == ?principal };`),
		cedar.TemplateFromJSON([]byte("{")), cedar.TemplateFromJSON([]byte("null")),
	} {
		if _, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "bad", template); err == nil {
			t.Fatalf("accepted malformed template %s", template.Text())
		}
	}
	set, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "share", cedar.TemplateFromCedar(shareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	for _, bindings := range []cedar.SlotBindings{
		{"?action": cedar.NewEntityUID("Action", "view")},
		{cedar.PrincipalSlot: cedar.NewEntityUID("not a type", "alice"), cedar.ResourceSlot: cedar.NewEntityUID("Photo", "beach")},
	} {
		if _, err := rt.LinkTemplate(ctx, set, "share", "bad", bindings); err == nil {
			t.Fatal("accepted invalid slot/UID")
		}
	}
	if _, err := rt.Templates(ctx, cedar.PoliciesFromJSON([]byte(`{"templates":{},"staticPolicies":{},"templateLinks":[{"templateId":"missing","newId":"bad","values":{}}]}`))); err == nil {
		t.Fatal("accepted dangling link")
	}
}

func TestTemplateConcurrentSnapshots(t *testing.T) {
	ctx, rt := context.Background(), testRuntime(t)
	set, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "share", cedar.TemplateFromCedar(shareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: set})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			linked, err := rt.LinkTemplate(ctx, set, "share", "same-id", shareBindings())
			if err != nil {
				t.Error(err)
				return
			}
			links, err := rt.TemplateLinks(ctx, linked)
			if err != nil || len(links) != 1 {
				t.Errorf("independent link result %v, %v", links, err)
			}
		})
	}
	wg.Wait()
	resp, err := a.Authorize(ctx, templateRequest())
	if err != nil || resp.Decision != cedar.Deny {
		t.Fatalf("existing authorizer changed: %+v, %v", resp, err)
	}
}

func FuzzTemplates(f *testing.F) {
	f.Add(shareTemplate, "share", "alice")
	f.Add("", "", "")
	f.Add(`permit(principal == ?principal, action, resource);`, "\x00", "a\n\"雪")
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, source, templateID, entityID string) {
		if len(source)+len(templateID)+len(entityID) > 8192 || nesting(source) > maxFuzzNesting {
			t.Skip()
		}
		ctx := context.Background()
		set, err := rt.AddTemplate(ctx, cedar.PolicySet{}, templateID, cedar.TemplateFromCedar(source))
		checkNoFault(t, err)
		if err != nil {
			return
		}
		templates, err := rt.Templates(ctx, set)
		if err != nil || len(templates) != 1 {
			t.Fatalf("successful add cannot be inspected: %v, %v", templates, err)
		}
		bindings := make(cedar.SlotBindings)
		for _, slot := range templates[0].Slots {
			bindings[slot] = cedar.NewEntityUID("User", entityID)
		}
		linked, err := rt.LinkTemplate(ctx, set, templates[0].ID, templates[0].ID+"-linked", bindings)
		if err != nil {
			checkNoFault(t, err)
			if !utf8.ValidString(entityID) {
				return
			}
			t.Fatalf("binding discovered slots failed: %v", err)
		}
		unlinked, err := rt.UnlinkTemplate(ctx, linked, templates[0].ID+"-linked")
		if err != nil || !reflect.DeepEqual(normalizedPolicyJSON(t, []byte(set.Text())), normalizedPolicyJSON(t, []byte(unlinked.Text()))) {
			t.Fatalf("link/unlink did not restore set: %v", err)
		}
	})
}

func equalTemplateMessages(a, b []cedar.PolicyMessage) bool {
	sort.Slice(a, func(i, j int) bool {
		if a[i].PolicyID != a[j].PolicyID {
			return a[i].PolicyID < a[j].PolicyID
		}
		return a[i].Message < a[j].Message
	})
	sort.Slice(b, func(i, j int) bool {
		if b[i].PolicyID != b[j].PolicyID {
			return b[i].PolicyID < b[j].PolicyID
		}
		return b[i].Message < b[j].Message
	})
	return reflect.DeepEqual(a, b)
}

func TestTemplateRejectsInvalidUTF8(t *testing.T) {
	ctx, rt := context.Background(), testRuntime(t)
	bad := string([]byte{0xff})
	set := cedar.PolicySet{}
	calls := []func() error{
		func() error {
			_, err := rt.AddTemplate(ctx, set, bad, cedar.TemplateFromCedar(shareTemplate))
			return err
		},
		func() error { _, err := rt.AddTemplate(ctx, set, "t", cedar.TemplateFromCedar(bad)); return err },
		func() error { _, err := rt.Templates(ctx, cedar.PoliciesFromCedar(bad)); return err },
		func() error { _, err := rt.LinkTemplate(ctx, set, bad, "p", nil); return err },
		func() error { _, err := rt.LinkTemplate(ctx, set, "t", bad, nil); return err },
		func() error {
			_, err := rt.LinkTemplate(ctx, set, "t", "p", cedar.SlotBindings{cedar.PrincipalSlot: cedar.NewEntityUID("User", bad)})
			return err
		},
		func() error {
			_, err := rt.LinkTemplate(ctx, set, "t", "p", cedar.SlotBindings{cedar.PrincipalSlot: cedar.NewEntityUID(bad, "a")})
			return err
		},
		func() error {
			_, err := rt.LinkTemplate(ctx, set, "t", "p", cedar.SlotBindings{cedar.SlotID(bad): cedar.NewEntityUID("User", "a")})
			return err
		},
		func() error { _, err := rt.UnlinkTemplate(ctx, set, bad); return err },
		func() error { _, err := rt.RemoveTemplate(ctx, set, bad); return err },
	}
	for i, call := range calls {
		var ce *cedar.Error
		if err := call(); !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestTemplateDiagnosticIDs(t *testing.T) {
	ctx, rt := context.Background(), testRuntime(t)
	templateID, policyID := "template\\\"\n\x00雪", "linked\\\"\n\x00雪"
	set, err := rt.AddTemplate(ctx, cedar.PolicySet{}, templateID, cedar.TemplateFromCedar(`permit(principal == ?principal, action, resource) when { context.missing };`))
	if err != nil {
		t.Fatal(err)
	}
	set, err = rt.LinkTemplate(ctx, set, templateID, policyID, cedar.SlotBindings{cedar.PrincipalSlot: cedar.NewEntityUID("User", "alice")})
	if err != nil {
		t.Fatal(err)
	}
	validation, err := rt.Validate(ctx, cedar.SchemaFromCedar(templateSchema), set)
	if err != nil || validation.Passed || len(validation.Errors) == 0 {
		t.Fatalf("invalid context reference: %+v, %v", validation, err)
	}
	for _, message := range validation.Errors {
		if message.PolicyID != templateID && message.PolicyID != policyID {
			t.Fatalf("escaped validation ID %q", message.PolicyID)
		}
	}
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: set})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	result, err := a.Authorize(ctx, templateRequest())
	if err != nil || result.Decision != cedar.Deny || len(result.Errors) != 1 || result.Errors[0].PolicyID != policyID {
		t.Fatalf("evaluation diagnostic %+v, %v", result, err)
	}
}
