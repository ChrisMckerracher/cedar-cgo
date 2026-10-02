package cedar_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

type propEditOp struct {
	add  bool
	stem string
}

// Add→list→remove sequences keep the set consistent with a Go-side model of IDs.
func TestPropertyPolicyEditSequences(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		ops := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) propEditOp {
			return propEditOp{add: rapid.Bool().Draw(t, "add"), stem: propGenPolicyID().Draw(t, "stem")}
		}), 2, 8).Draw(pt, "ops")
		set := cedar.ParsedPolicySet{}.Source()
		model := map[string]bool{}
		for i, op := range ops {
			if op.add {
				// The index suffix keeps IDs unique no matter what rapid redraws.
				id := fmt.Sprintf("%s%d", op.stem, i)
				p, err := rt.ParsePolicy(ctx, id, propGenPolicy(id).Draw(pt, "policy"))
				if err != nil {
					pt.Fatalf("op %d: parse: %v", i, err)
				}
				next, err := rt.AddPolicy(ctx, set, p)
				if err != nil {
					pt.Fatalf("op %d: add rejected a fresh ID: %v", i, err)
				}
				model[id] = true
				set = next.Source()
			} else {
				id := propGenPolicyID().Draw(pt, "id")
				if keys := slices.Collect(maps.Keys(model)); len(keys) > 0 && rapid.Bool().Draw(pt, "hit") {
					id = rapid.SampledFrom(keys).Draw(pt, "present")
				}
				next, err := rt.RemovePolicy(ctx, set, id)
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
			snapshot, err := rt.ParsePolicySet(ctx, set)
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
	rt := testRuntime(t)
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		id := propGenPolicyID().Draw(pt, "id")
		p, err := rt.ParsePolicy(ctx, id, propGenPolicy(id).Draw(pt, "policy"))
		if err != nil {
			pt.Fatalf("parse: %v", err)
		}
		fromJSON, err := rt.PolicyFromJSON(ctx, p.ID(), p.JSON())
		if err != nil {
			pt.Fatalf("JSON view rejected: %v", err)
		}
		propSameJSON(pt, fromJSON.JSON(), p.JSON())
		syntax, err := p.Syntax()
		if err != nil {
			pt.Fatalf("syntax: %v", err)
		}
		fromSyntax, err := rt.PolicyFromSyntax(ctx, syntax)
		if err != nil {
			pt.Fatalf("EST view rejected: %v", err)
		}
		again, err := fromSyntax.Syntax()
		if err != nil {
			pt.Fatalf("reconstructed EST: %v", err)
		}
		b, _ := json.Marshal(syntax)
		c, _ := json.Marshal(again)
		propSameJSON(pt, b, c)
		set, err := rt.AddPolicy(ctx, cedar.ParsedPolicySet{}.Source(), p)
		if err != nil {
			pt.Fatalf("add: %v", err)
		}
		reread, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromJSON(set.JSON()))
		if err != nil {
			pt.Fatalf("set JSON rejected: %v", err)
		}
		propSameJSON(pt, reread.JSON(), set.JSON())
	})
}

// Adding and removing a policy restores the set exactly; unrelated policies
// keep their JSON untouched.
func TestPropertyEditsIsolateUnrelatedPolicies(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		first, err := rt.ParsePolicy(ctx, "first", propGenPolicy("first").Draw(pt, "first"))
		if err != nil {
			pt.Fatalf("parse first: %v", err)
		}
		base, err := rt.AddPolicy(ctx, cedar.ParsedPolicySet{}.Source(), first)
		if err != nil {
			pt.Fatalf("add first: %v", err)
		}
		second, err := rt.ParsePolicy(ctx, "second", propGenPolicy("second").Draw(pt, "second"))
		if err != nil {
			pt.Fatalf("parse second: %v", err)
		}
		grown, err := rt.AddPolicy(ctx, base.Source(), second)
		if err != nil {
			pt.Fatalf("add second: %v", err)
		}
		if p, ok := grown.Policy("first"); !ok {
			pt.Fatal("adding a policy dropped an unrelated policy")
		} else {
			propSameJSON(pt, p.JSON(), first.JSON())
		}
		restored, err := rt.RemovePolicy(ctx, grown.Source(), "second")
		if err != nil {
			pt.Fatalf("remove second: %v", err)
		}
		propSameJSON(pt, restored.JSON(), base.JSON())
	})
}
