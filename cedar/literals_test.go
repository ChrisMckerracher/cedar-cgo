package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

func TestSimultaneousEntityLiteralSubstitution(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	a, b, c := cedar.NewEntityUID("User", "A"), cedar.NewEntityUID("User", "B"), cedar.NewEntityUID("User", "C")
	source := cedar.PoliciesFromCedar(`@note("雪") permit(principal == User::"A", action, resource) when { resource == User::"B" && "User::\"A\"" == "User::\"A\"" };`)
	inventory, err := rt.EntityLiterals(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory.Policies["policy0"], []cedar.EntityUID{a, b}) {
		t.Fatalf("inventory %+v", inventory)
	}
	changed, err := rt.SubstituteEntityLiterals(ctx, source, map[cedar.EntityUID]cedar.EntityUID{a: b, b: c})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err = rt.EntityLiterals(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory.Policies["policy0"], []cedar.EntityUID{b, c}) {
		t.Fatalf("substitution cascaded: %+v", inventory)
	}
	if !strings.Contains(changed.Text(), `User::\"A\"`) {
		t.Fatal("string literal changed")
	}
	parsed, err := rt.ParsePolicySet(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := parsed.Policy("policy0")
	if !ok || policy.Annotations()["note"] != "雪" {
		t.Fatal("policy identity or annotation changed")
	}
	authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: changed})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedar.Request{Principal: b, Action: cedar.NewEntityUID("Action", "view"), Resource: c})
	if err != nil || response.Decision != cedar.Allow {
		t.Fatalf("transformed request: %+v %v", response, err)
	}
}

func TestTemplateEntityLiteralSubstitution(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	a, b := cedar.NewEntityUID("User", "A"), cedar.NewEntityUID("User", "B")
	source, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "template", cedar.TemplateFromCedar(`@note("雪") permit(principal == ?principal, action, resource == User::"A");`))
	if err != nil {
		t.Fatal(err)
	}
	source, err = rt.LinkTemplate(ctx, source, "template", "link", cedar.SlotBindings{cedar.PrincipalSlot: a})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := rt.SubstituteEntityLiterals(ctx, source, map[cedar.EntityUID]cedar.EntityUID{a: b})
	if err != nil {
		t.Fatal(err)
	}
	templates, err := rt.Templates(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 1 || templates[0].ID != "template" || templates[0].Annotations["note"] != "雪" || !reflect.DeepEqual(templates[0].Slots, []cedar.SlotID{cedar.PrincipalSlot}) {
		t.Fatalf("template identity changed: %+v", templates)
	}
	links, err := rt.TemplateLinks(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].PolicyID != "link" || links[0].TemplateID != "template" || links[0].Bindings[cedar.PrincipalSlot] != b {
		t.Fatalf("link identity or bindings: %+v", links)
	}
	inventory, err := rt.EntityLiterals(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory.Templates["template"], []cedar.EntityUID{b}) {
		t.Fatalf("template literals: %+v", inventory)
	}
	authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: changed})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedar.Request{Principal: b, Action: cedar.NewEntityUID("Action", "view"), Resource: b})
	if err != nil || response.Decision != cedar.Allow {
		t.Fatalf("transformed template request: %+v %v", response, err)
	}
}

func TestEntityLiteralBoundaries(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	source := cedar.PoliciesFromCedar(`permit(principal, action, resource);`)
	inventory, err := rt.EntityLiterals(ctx, source)
	if err != nil || len(inventory.Policies["policy0"]) != 0 {
		t.Fatalf("empty literals: %+v %v", inventory, err)
	}
	uid := cedar.NewEntityUID("User", "雪")
	for _, mapping := range []map[cedar.EntityUID]cedar.EntityUID{nil, {uid: uid}} {
		changed, err := rt.SubstituteEntityLiterals(ctx, source, mapping)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := rt.ParsePolicySet(ctx, changed)
		if err != nil || len(parsed.Policies()) != 1 {
			t.Fatalf("identity map changed set: %+v %v", parsed, err)
		}
	}
	for _, target := range []cedar.EntityUID{cedar.NewEntityUID("invalid type", "x"), cedar.NewEntityUID("User", string([]byte{0xff}))} {
		_, err := rt.SubstituteEntityLiterals(ctx, source, map[cedar.EntityUID]cedar.EntityUID{uid: target})
		var ce *cedar.Error
		if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
			t.Fatalf("invalid target: %v", err)
		}
	}
}

func TestPropertySimultaneousEntityLiteralSubstitution(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	source := cedar.PoliciesFromCedar(`permit(principal == User::"A", action, resource == User::"B");`)
	a, b := cedar.NewEntityUID("User", "A"), cedar.NewEntityUID("User", "B")
	rapid.Check(t, func(pt *rapid.T) {
		targetA := cedar.NewEntityUID("User", rapid.SampledFrom([]string{"A", "B", "C", "雪"}).Draw(pt, "targetA"))
		targetB := cedar.NewEntityUID("User", rapid.SampledFrom([]string{"A", "B", "C", "雪"}).Draw(pt, "targetB"))
		changed, err := rt.SubstituteEntityLiterals(ctx, source, map[cedar.EntityUID]cedar.EntityUID{a: targetA, b: targetB})
		if err != nil {
			pt.Fatal(err)
		}
		got, err := rt.EntityLiterals(ctx, changed)
		if err != nil {
			pt.Fatal(err)
		}
		values := got.Policies["policy0"]
		if len(values) != 2 {
			pt.Fatalf("literal count %+v", values)
		}
		count := map[cedar.EntityUID]int{}
		for _, v := range values {
			count[v]++
		}
		count[targetA]--
		count[targetB]--
		for _, n := range count {
			if n != 0 {
				pt.Fatalf("substitution cascaded: %+v", values)
			}
		}
	})
}

func TestEntityLiteralNativeFixtures(t *testing.T) {
	var input []struct {
		Name, Policies string
		PoliciesJSON   json.RawMessage `json:"policies_json"`
		Replacements   []struct{ From, To cedar.EntityUID }
		Link           *struct {
			TemplateID string `json:"template_id"`
			ID         string
			Principal  cedar.EntityUID
		}
	}
	var expected []struct {
		Name          string
		Before, After cedar.EntityLiteralInventory
		Policies      json.RawMessage
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/literals/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/literals/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testRuntime(t)
	ctx := context.Background()
	for i, tc := range input {
		t.Run(tc.Name, func(t *testing.T) {
			source := cedar.PoliciesFromCedar(tc.Policies)
			if len(tc.PoliciesJSON) != 0 {
				source = cedar.PoliciesFromJSON(tc.PoliciesJSON)
			}
			if tc.Link != nil {
				var err error
				source, err = rt.LinkTemplate(ctx, source, tc.Link.TemplateID, tc.Link.ID, cedar.SlotBindings{cedar.PrincipalSlot: tc.Link.Principal})
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := rt.EntityLiterals(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			mapping := map[cedar.EntityUID]cedar.EntityUID{}
			for _, entry := range tc.Replacements {
				mapping[entry.From] = entry.To
			}
			changed, err := rt.SubstituteEntityLiterals(ctx, source, mapping)
			if err != nil {
				t.Fatal(err)
			}
			after, err := rt.EntityLiterals(ctx, changed)
			if err != nil {
				t.Fatal(err)
			}
			want := expected[i]
			if want.Name != tc.Name || !reflect.DeepEqual(before, want.Before) || !reflect.DeepEqual(after, want.After) {
				t.Fatalf("inventory differs: before %+v after %+v native %+v", before, after, want)
			}
			sameJSON(t, []byte(changed.Text()), want.Policies)
		})
	}
}

func FuzzEntityLiteralSubstitution(f *testing.F) {
	f.Add(`permit(principal == User::"A", action, resource);`, "A", "B")
	f.Add(`permit(principal == ?principal, action, resource == User::"雪");`, "雪", "C")
	f.Add("", "A", "A")
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, source, from, to string) {
		if len(source)+len(from)+len(to) > 4096 || nesting(source) > 40 {
			t.Skip()
		}
		changed, err := rt.SubstituteEntityLiterals(context.Background(), cedar.PoliciesFromCedar(source), map[cedar.EntityUID]cedar.EntityUID{cedar.NewEntityUID("User", from): cedar.NewEntityUID("User", to)})
		checkNoFault(t, err)
		if err != nil {
			return
		}
		if _, err := rt.ParsePolicySet(context.Background(), changed); err != nil {
			t.Fatal("substituted set cannot be parsed:", err)
		}
		if _, err := rt.EntityLiterals(context.Background(), changed); err != nil {
			t.Fatal("substituted set cannot be inspected:", err)
		}
	})
}

func TestEntityLiteralInventoryJSONRoundTrip(t *testing.T) {
	id := "quote\"\nslash\\\x00雪"
	for _, input := range []cedar.EntityLiteralInventory{
		{},
		{Policies: map[string][]cedar.EntityUID{"": nil, id: {cedar.NewEntityUID("User", "雪\x00")}}, Templates: map[string][]cedar.EntityUID{"template": {}}},
	} {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var output cedar.EntityLiteralInventory
		if err := json.Unmarshal(data, &output); err != nil || !reflect.DeepEqual(input, output) {
			t.Fatalf("inventory identity changed: %+v %s %v", output, data, err)
		}
	}
	bad := string([]byte{0xff})
	for _, input := range []cedar.EntityLiteralInventory{
		{Policies: map[string][]cedar.EntityUID{bad: {}}},
		{Templates: map[string][]cedar.EntityUID{bad: {}}},
		{Policies: map[string][]cedar.EntityUID{"x": {cedar.NewEntityUID(bad, "x")}}},
		{Templates: map[string][]cedar.EntityUID{"x": {cedar.NewEntityUID("User", bad)}}},
	} {
		if data, err := json.Marshal(input); err == nil || data != nil {
			t.Fatalf("invalid identity normalized: %s %v", data, err)
		}
	}
}
