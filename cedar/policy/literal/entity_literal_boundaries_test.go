package literal_test

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	rapid "pgregory.net/rapid"
	testing "testing"
)

func TestEntityLiteralBoundaries(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	source := cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource);`)
	inventory, err := rt.PolicyLiterals().EntityLiterals(ctx, source)
	if err != nil || len(inventory.Policies["policy0"]) != 0 {
		t.Fatalf("empty literals: %+v %v", inventory, err)
	}
	uid := entityuid.NewEntityUID("User", "雪")
	for _, mapping := range []map[entityuid.EntityUID]entityuid.EntityUID{nil, {uid: uid}} {
		changed, err := rt.PolicyLiterals().SubstituteEntityLiterals(ctx, source, mapping)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := rt.Policies().ParsePolicySet(ctx, changed)
		if err != nil || len(parsed.Policies()) != 1 {
			t.Fatalf("identity map changed set: %+v %v", parsed, err)
		}
	}
	for _, target := range []entityuid.EntityUID{entityuid.NewEntityUID("invalid type", "x"), entityuid.NewEntityUID("User", string([]byte{0xff}))} {
		_, err := rt.PolicyLiterals().SubstituteEntityLiterals(ctx, source, map[entityuid.EntityUID]entityuid.EntityUID{uid: target})
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
			t.Fatalf("invalid target: %v", err)
		}
	}
}

func TestPropertySimultaneousEntityLiteralSubstitution(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	source := cedarpolicy.PoliciesFromCedar(`permit(principal == User::"A", action, resource == User::"B");`)
	a, b := entityuid.NewEntityUID("User", "A"), entityuid.NewEntityUID("User", "B")
	rapid.Check(t, func(pt *rapid.T) {
		targetA := entityuid.NewEntityUID("User", rapid.SampledFrom([]string{"A", "B", "C", "雪"}).Draw(pt, "targetA"))
		targetB := entityuid.NewEntityUID("User", rapid.SampledFrom([]string{"A", "B", "C", "雪"}).Draw(pt, "targetB"))
		changed, err := rt.PolicyLiterals().SubstituteEntityLiterals(ctx, source, map[entityuid.EntityUID]entityuid.EntityUID{a: targetA, b: targetB})
		if err != nil {
			pt.Fatal(err)
		}
		got, err := rt.PolicyLiterals().EntityLiterals(ctx, changed)
		if err != nil {
			pt.Fatal(err)
		}
		values := got.Policies["policy0"]
		if len(values) != 2 {
			pt.Fatalf("literal count %+v", values)
		}
		count := map[entityuid.EntityUID]int{}
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
