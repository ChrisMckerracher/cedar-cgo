package template_test

import (
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
)

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
	original := cedarpolicy.PoliciesFromJSON(data)
	check := func(set cedarpolicy.PolicySet) {
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
	ctx, rt := context.Background(), testsupport.TestRuntime(t)
	set, err := rt.Templates().AddTemplate(ctx, original, "share", template.TemplateFromCedar(testsupport.ShareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	set, err = rt.Templates().LinkTemplate(ctx, set, "share", "linked", testsupport.ShareBindings())
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	set, err = rt.Templates().UnlinkTemplate(ctx, set, "linked")
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	set, err = rt.Templates().RemoveTemplate(ctx, set, "share")
	if err != nil {
		t.Fatal(err)
	}
	check(set)
	if !reflect.DeepEqual(testsupport.NormalizedPolicyJSON(t, []byte(original.Text())), testsupport.NormalizedPolicyJSON(t, []byte(set.Text()))) {
		t.Fatalf("template round trip changed the original policy set:\noriginal %s\nresult %s", original.Text(), set.Text())
	}
}
