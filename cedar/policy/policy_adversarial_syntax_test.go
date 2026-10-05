package policy_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	time "time"
)

func TestPolicyAdversarialSyntax(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	f := testsupport.LoadPolicyFixture(t)
	cases := []struct {
		name string
		edit func(*cedarpolicy.PolicySyntax)
	}{
		{"invalid-effect", func(s *cedarpolicy.PolicySyntax) { s.Effect = "allow" }},
		{"invalid-type", func(s *cedarpolicy.PolicySyntax) { s.Principal.EntityType = "not a type" }},
		{"extra-constraint-field", func(s *cedarpolicy.PolicySyntax) { s.Resource.EntityType = "User" }},
		{"extra-principal-type", func(s *cedarpolicy.PolicySyntax) { s.Principal.Kind = cedarpolicy.ConstraintAny }},
		{"extra-principal-entity", func(s *cedarpolicy.PolicySyntax) {
			e := entityuid.NewEntityUID("User", "a")
			s.Principal = cedarpolicy.ScopeConstraint{Kind: cedarpolicy.ConstraintAny, Entity: &e}
		}},
		{"extra-resource-entity", func(s *cedarpolicy.PolicySyntax) { e := entityuid.NewEntityUID("Photo", "p"); s.Resource.Entity = &e }},
		{"extra-action-entity", func(s *cedarpolicy.PolicySyntax) { e := entityuid.NewEntityUID("Action", "view"); s.Action.Entity = &e }},
		{"extra-action-set", func(s *cedarpolicy.PolicySyntax) { s.Action.Entities = []entityuid.EntityUID{} }},
		{"missing-equality-entity", func(s *cedarpolicy.PolicySyntax) { s.Resource.Kind = cedarpolicy.ConstraintEq }},
		{"slot-in-clause", func(s *cedarpolicy.PolicySyntax) { s.Conditions[0].Body = json.RawMessage(`{"Slot":"?principal"}`) }},
		{"invalid-clause", func(s *cedarpolicy.PolicySyntax) { s.Conditions[0].Kind = "otherwise" }},
		{"overflow", func(s *cedarpolicy.PolicySyntax) {
			s.Conditions[0].Body = json.RawMessage(`{"Value":9223372036854775808}`)
		}},
		{"invalid-annotation", func(s *cedarpolicy.PolicySyntax) { s.Annotations["has space"] = "x" }},
		{"invalid-JSON", func(s *cedarpolicy.PolicySyntax) { s.Conditions[0].Body = json.RawMessage(`{`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s cedarpolicy.PolicySyntax
			b, _ := json.Marshal(f.Constructed.Syntax)
			if err := json.Unmarshal(b, &s); err != nil {
				t.Fatal(err)
			}
			tc.edit(&s)
			if _, err := rt.Policies().PolicyFromSyntax(ctx, s); err == nil {
				t.Fatal("invalid syntax accepted")
			} else if errors.Is(err, diagnostic.ErrFault) {
				t.Fatalf("invalid syntax faulted: %v", err)
			}
		})
	}
	_, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar(""), cedarpolicy.ParsedPolicy{})
	if err == nil {
		t.Fatal("accepted zero policy")
	}
	// Duplicate object keys must reach Rust's PolicySet parser intact.
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
	rt := testsupport.TestRuntime(t)
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
