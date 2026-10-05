package policy_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	json "encoding/json"
	fmt "fmt"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	maps "maps"
	rapid "pgregory.net/rapid"
	slices "slices"
	testing "testing"
)

// Add→list→remove sequences keep the set consistent with a Go-side model of IDs.
func TestPropertyPolicyEditSequences(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		ops := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) generator.PropEditOp {
			return generator.PropEditOp{Add: rapid.Bool().Draw(t, "add"), Stem: generator.PropGenPolicyID().Draw(t, "stem")}
		}), 2, 8).Draw(pt, "ops")
		set := cedarpolicy.ParsedPolicySet{}.Source()
		model := map[string]bool{}
		for i, op := range ops {
			if op.Add {
				// The index suffix keeps IDs unique no matter what rapid redraws.
				id := fmt.Sprintf("%s%d", op.Stem, i)
				p, err := rt.Policies().ParsePolicy(ctx, id, generator.PropGenPolicy(id).Draw(pt, "policy"))
				if err != nil {
					pt.Fatalf("op %d: parse: %v", i, err)
				}
				next, err := rt.Policies().AddPolicy(ctx, set, p)
				if err != nil {
					pt.Fatalf("op %d: add rejected a fresh ID: %v", i, err)
				}
				model[id] = true
				set = next.Source()
			} else {
				id := generator.PropGenPolicyID().Draw(pt, "id")
				if keys := slices.Sorted(maps.Keys(model)); len(keys) > 0 && rapid.Bool().Draw(pt, "hit") {
					id = rapid.SampledFrom(keys).Draw(pt, "present")
				}
				next, err := rt.Policies().RemovePolicy(ctx, set, id)
				if model[id] {
					if err != nil {
						pt.Fatalf("op %d: remove rejected a present ID: %v", i, err)
					}
					delete(model, id)
					set = next.Source()
				} else if err == nil {
					pt.Fatalf("op %d: remove accepted a missing ID %q", i, id)
				}
			}
			snapshot, err := rt.Policies().ParsePolicySet(ctx, set)
			if err != nil {
				pt.Fatalf("op %d: set no longer parses: %v", i, err)
			}
			ids := make([]string, 0, len(model))
			for _, p := range snapshot.Policies() {
				ids = append(ids, p.ID())
			}
			slices.Sort(ids)
			if want := slices.Sorted(maps.Keys(model)); !slices.Equal(ids, want) {
				pt.Fatalf("op %d: set IDs %v disagree with model %v", i, ids, want)
			}
		}
	})
}

// The JSON and EST views of a parsed policy round-trip through their parsers.
func TestPropertyPolicyViewsRoundtrip(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		id := generator.PropGenPolicyID().Draw(pt, "id")
		p, err := rt.Policies().ParsePolicy(ctx, id, generator.PropGenPolicy(id).Draw(pt, "policy"))
		if err != nil {
			pt.Fatalf("parse: %v", err)
		}
		fromJSON, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON())
		if err != nil {
			pt.Fatalf("JSON view rejected: %v", err)
		}
		generator.PropSameJSON(pt, fromJSON.JSON(), p.JSON())
		syntax, err := p.Syntax()
		if err != nil {
			pt.Fatalf("syntax: %v", err)
		}
		fromSyntax, err := rt.Policies().PolicyFromSyntax(ctx, syntax)
		if err != nil {
			pt.Fatalf("EST view rejected: %v", err)
		}
		again, err := fromSyntax.Syntax()
		if err != nil {
			pt.Fatalf("reconstructed EST: %v", err)
		}
		b, _ := json.Marshal(syntax)
		c, _ := json.Marshal(again)
		generator.PropSameJSON(pt, b, c)
		set, err := rt.Policies().AddPolicy(ctx, cedarpolicy.ParsedPolicySet{}.Source(), p)
		if err != nil {
			pt.Fatalf("add: %v", err)
		}
		reread, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromJSON(set.JSON()))
		if err != nil {
			pt.Fatalf("set JSON rejected: %v", err)
		}
		generator.PropSameJSON(pt, reread.JSON(), set.JSON())
	})
}
