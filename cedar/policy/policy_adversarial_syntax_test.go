package policy_test

import (
	bytes "bytes"
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	jsonassert "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/jsonassert"
	policysupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/policy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
	time "time"
)

func TestPolicyAdversarialSyntax(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	f := LoadPolicyFixture(t)
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"invalid-effect", func(s map[string]any) { s["effect"] = "allow" }},
		{"invalid-type", func(s map[string]any) { s["principal"].(map[string]any)["entity_type"] = "not a type" }},
		{"extra-constraint-field", func(s map[string]any) { s["resource"].(map[string]any)["entity_type"] = "User" }},
		{"extra-principal-type", func(s map[string]any) { s["principal"].(map[string]any)["op"] = "All" }},
		{"extra-principal-entity", func(s map[string]any) {
			s["principal"] = map[string]any{"op": "All", "entity": map[string]string{"type": "User", "id": "a"}}
		}},
		{"extra-resource-entity", func(s map[string]any) {
			s["resource"].(map[string]any)["entity"] = map[string]string{"type": "Photo", "id": "p"}
		}},
		{"extra-action-entity", func(s map[string]any) {
			s["action"].(map[string]any)["entity"] = map[string]string{"type": "Action", "id": "view"}
		}},
		{"extra-action-set", func(s map[string]any) { s["action"].(map[string]any)["entities"] = []any{} }},
		{"missing-equality-entity", func(s map[string]any) { s["resource"].(map[string]any)["op"] = "==" }},
		{"slot-in-clause", func(s map[string]any) {
			s["conditions"].([]any)[0].(map[string]any)["body"] = json.RawMessage(`{"Slot":"?principal"}`)
		}},
		{"invalid-clause", func(s map[string]any) { s["conditions"].([]any)[0].(map[string]any)["kind"] = "otherwise" }},
		{"overflow", func(s map[string]any) {
			s["conditions"].([]any)[0].(map[string]any)["body"] = json.RawMessage(`{"Value":9223372036854775808}`)
		}},
		{"invalid-annotation", func(s map[string]any) { s["annotations"].(map[string]any)["has space"] = "x" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var document map[string]any
			decoder := json.NewDecoder(bytes.NewReader(f.Constructed.JSON))
			decoder.UseNumber()
			if err := decoder.Decode(&document); err != nil {
				t.Fatal(err)
			}
			tc.edit(document)
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := rt.Policies().PolicyFromJSON(ctx, f.Constructed.Syntax.ID, data)
			fields := map[string]string{
				"extra-constraint-field": "resource", "extra-principal-type": "principal", "extra-principal-entity": "principal",
				"extra-resource-entity": "resource", "extra-action-entity": "action", "extra-action-set": "action",
			}
			if field := fields[tc.name]; field != "" {
				// Cedar JSON discards fields that do not apply to the selected scope operation.
				if err != nil {
					t.Fatal(err)
				}
				canonical := policysupport.MustPolicyJSON(t, parsed)
				constraint, err := json.Marshal(canonical[field])
				if err != nil {
					t.Fatal(err)
				}
				jsonassert.Equal(t, constraint, []byte(`{"op":"All"}`))
				return
			}
			if err == nil {
				t.Fatal("invalid syntax accepted")
			} else if errors.Is(err, diagnostic.ErrFault) {
				t.Fatalf("invalid syntax faulted: %v", err)
			}
		})
	}
	t.Run("invalid-JSON", func(t *testing.T) {
		_, err := rt.Policies().PolicyFromJSON(ctx, "invalid", []byte("{"))
		if err == nil || errors.Is(err, diagnostic.ErrFault) {
			t.Fatalf("invalid JSON: %v", err)
		}
	})
	_, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar(""), cedarpolicy.ParsedPolicy{})
	if err == nil {
		t.Fatal("accepted zero policy")
	}
	p, err := rt.Policies().ParsePolicy(ctx, "p", "permit(principal,action,resource);")
	if err != nil {
		t.Fatal(err)
	}
	duplicate := `{"templates":{},"staticPolicies":{"p":` + string(p.JSON()) + `,"p":` + string(p.JSON()) + `},"templateLinks":[]}`
	if _, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromJSON([]byte(duplicate))); err == nil {
		t.Fatal("duplicate JSON IDs accepted")
	}
}

func TestPolicyCancellation(t *testing.T) {
	rt := testruntime.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := rt.Policies().ParsePolicy(ctx, "p", "permit(principal,action,resource);")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	_, err = rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromCedar(""))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error: %v", err)
	}
	if _, err := rt.Policies().ParsePolicy(context.Background(), "fresh", "permit(principal,action,resource);"); err != nil {
		t.Fatal("canceled operation poisoned runtime:", err)
	}
}
