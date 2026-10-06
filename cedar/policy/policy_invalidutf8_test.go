package policy_test

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func TestPolicyInvalidUTF8(t *testing.T) {
	rt := testruntime.New(t)
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
			_, e := rt.Policies().PolicyFromJSON(ctx, invalid, LoadPolicyFixture(t).Constructed.JSON)
			return e
		},
		func() error {
			data := []byte(`{"effect":"permit","conditions":[{"kind":"when","body":{"Value":"` + invalid + `"}}]}`)
			_, e := rt.Policies().PolicyFromJSON(ctx, "id", data)
			return e
		},
		func() error {
			data := []byte(`{"annotations":{"` + invalid + `":"x"}}`)
			_, e := rt.Policies().PolicyFromJSON(ctx, "id", data)
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
