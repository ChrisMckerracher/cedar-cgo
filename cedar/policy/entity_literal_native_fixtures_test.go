package policy_test

import (
	context "context"
	json "encoding/json"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
)

func TestEntityLiteralNativeFixtures(t *testing.T) {
	var input []struct {
		Name, Policies string
		PoliciesJSON   json.RawMessage `json:"policies_json"`
		Replacements   []struct{ From, To entityuid.EntityUID }
		Link           *struct {
			TemplateID string `json:"template_id"`
			ID         string
			Principal  entityuid.EntityUID
		}
	}
	var expected []struct {
		Name          string
		Before, After cedarpolicy.EntityLiteralInventory
		Policies      json.RawMessage
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/literals/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/literals/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	for i, tc := range input {
		t.Run(tc.Name, func(t *testing.T) {
			source := cedarpolicy.PoliciesFromCedar(tc.Policies)
			if len(tc.PoliciesJSON) != 0 {
				source = cedarpolicy.PoliciesFromJSON(tc.PoliciesJSON)
			}
			if tc.Link != nil {
				var err error
				source, err = rt.Templates().LinkTemplate(ctx, source, tc.Link.TemplateID, tc.Link.ID, template.SlotBindings{template.PrincipalSlot: tc.Link.Principal})
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := rt.Policies().EntityLiterals(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			mapping := map[entityuid.EntityUID]entityuid.EntityUID{}
			for _, entry := range tc.Replacements {
				mapping[entry.From] = entry.To
			}
			changed, err := rt.Policies().SubstituteEntityLiterals(ctx, source, mapping)
			if err != nil {
				t.Fatal(err)
			}
			after, err := rt.Policies().EntityLiterals(ctx, changed)
			if err != nil {
				t.Fatal(err)
			}
			want := expected[i]
			if want.Name != tc.Name || !reflect.DeepEqual(before, want.Before) || !reflect.DeepEqual(after, want.After) {
				t.Fatalf("inventory differs: before %+v after %+v native %+v", before, after, want)
			}
			testsupport.SameJSON(t, []byte(changed.Text()), want.Policies)
		})
	}
}

func FuzzEntityLiteralSubstitution(f *testing.F) {
	f.Add(`permit(principal == User::"A", action, resource);`, "A", "B")
	f.Add(`permit(principal == ?principal, action, resource == User::"雪");`, "雪", "C")
	f.Add("", "A", "A")
	rt := testsupport.TestRuntime(f)
	f.Fuzz(func(t *testing.T, source, from, to string) {
		if len(source)+len(from)+len(to) > 4096 || testsupport.Nesting(source) > 40 {
			t.Skip()
		}
		changed, err := rt.Policies().SubstituteEntityLiterals(context.Background(), cedarpolicy.PoliciesFromCedar(source), map[entityuid.EntityUID]entityuid.EntityUID{entityuid.NewEntityUID("User", from): entityuid.NewEntityUID("User", to)})
		testsupport.CheckNoFault(t, err)
		if err != nil {
			return
		}
		if _, err := rt.Policies().ParsePolicySet(context.Background(), changed); err != nil {
			t.Fatal("substituted set cannot be parsed:", err)
		}
		if _, err := rt.Policies().EntityLiterals(context.Background(), changed); err != nil {
			t.Fatal("substituted set cannot be inspected:", err)
		}
	})
}
