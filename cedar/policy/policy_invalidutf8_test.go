package policy_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
)

func TestPolicyInvalidUTF8(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	invalid := string([]byte{0xff})
	source := "permit(principal,action,resource);"
	cases := []func() error{
		func() error { _, e := rt.Policies().ParsePolicy(ctx, invalid, source); return e },
		func() error { _, e := rt.Policies().ParsePolicy(ctx, "id", source+invalid); return e },
		func() error { _, e := rt.Policies().PolicyFromJSON(ctx, invalid, []byte(`{}`)); return e },
		func() error {
			_, e := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromCedar(invalid))
			return e
		},
		func() error {
			_, e := rt.Policies().RemovePolicy(ctx, cedarpolicy.PoliciesFromCedar(""), invalid)
			return e
		},
		func() error {
			s := testsupport.LoadPolicyFixture(t).Constructed.Syntax
			s.ID = invalid
			_, e := rt.Policies().PolicyFromSyntax(ctx, s)
			return e
		},
		func() error {
			s := testsupport.LoadPolicyFixture(t).Constructed.Syntax
			s.Conditions[0].Body = json.RawMessage(`{"Value":"` + invalid + `"}`)
			_, e := rt.Policies().PolicyFromSyntax(ctx, s)
			return e
		},
		func() error {
			s := testsupport.LoadPolicyFixture(t).Constructed.Syntax
			s.Annotations[invalid] = "x"
			_, e := rt.Policies().PolicyFromSyntax(ctx, s)
			return e
		},
		func() error {
			_, _, e := rt.Policies().MergePolicySets(ctx, cedarpolicy.PoliciesFromCedar(source+invalid), cedarpolicy.PoliciesFromCedar(source), false)
			return e
		},
		func() error {
			other := cedarpolicy.PoliciesFromJSON([]byte(`{"staticPolicies":{"` + invalid + `":{}}}`))
			_, _, e := rt.Policies().MergePolicySets(ctx, cedarpolicy.PoliciesFromCedar(source), other, true)
			return e
		},
	}
	for i, run := range cases {
		var e *diagnostic.Error
		if err := run(); !errors.As(err, &e) || e.Kind != diagnostic.KindInput {
			t.Fatalf("case %d: got %v", i, err)
		}
	}
}
