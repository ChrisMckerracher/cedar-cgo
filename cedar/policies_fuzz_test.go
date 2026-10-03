package cedar_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzPolicySyntax(f *testing.F) {
	fixture := loadPolicyFixture(f)
	seed, _ := json.Marshal(fixture.Constructed.Syntax)
	f.Add(string(seed))
	f.Add(`{"id":"","effect":"permit","principal":{"kind":"any"},"action":{"kind":"in","entities":[]},"resource":{"kind":"any"},"conditions":[{"kind":"when","body":{"Value":9223372036854775807}}]}`)
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 || nesting(input) > maxFuzzNesting {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var syntax cedar.PolicySyntax
		if json.Unmarshal([]byte(input), &syntax) != nil {
			// Invalid Go syntax envelopes still exercise the Rust policy JSON parser.
			_, err := rt.PolicyFromJSON(ctx, "fuzz", []byte(input))
			checkNoFault(t, err)
			if !utf8.ValidString(input) {
				requireUTF8InputError(t, err)
			}
			return
		}
		p, err := rt.PolicyFromSyntax(ctx, syntax)
		checkNoFault(t, err)
		if err != nil {
			return
		}
		if p.ID() != syntax.ID {
			t.Fatal("ID changed")
		}
		q, err := rt.PolicyFromJSON(ctx, p.ID(), p.JSON())
		if err != nil {
			t.Fatal("JSON round trip:", err)
		}
		sameJSON(t, q.JSON(), p.JSON())
		tree, err := p.Syntax()
		if err != nil {
			t.Fatal(err)
		}
		r, err := rt.PolicyFromSyntax(ctx, tree)
		if err != nil {
			t.Fatal("PST round trip:", err)
		}
		sameJSON(t, r.JSON(), p.JSON())
	})
}

func fuzzPolicyIDs(s cedar.ParsedPolicySet) []string {
	ids := make([]string, 0, 8)
	for _, p := range s.Policies() {
		ids = append(ids, p.ID())
	}
	slices.Sort(ids)
	return ids
}

// FuzzPolicyEdits drives add/remove sequences over a parsed policy set and
// requires every operation to either succeed with the inspected membership
// updated, or fail leaving the set coherent and reparseable.
func FuzzPolicyEdits(f *testing.F) {
	f.Add(`permit(principal, action, resource);`, `forbid(principal, action, resource);`, "p0", "p1", "p0")
	f.Add(`permit(principal, action, resource);`, `permit(principal, action, resource) when { 1 + };`, "dup", "dup", "dup")
	f.Add("", "", "", "", "")
	f.Add(`@id("x") permit(principal, action, resource) when { context.a };`, `forbid(principal, action, resource) unless { principal has b };`, "a\n\"雪", "\x00", "missing")
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, sourceA, sourceB, idA, idB, removeID string) {
		if len(sourceA)+len(sourceB)+len(idA)+len(idB)+len(removeID) > 8192 ||
			nesting(sourceA) > maxFuzzNesting || nesting(sourceB) > maxFuzzNesting {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		set := cedar.PolicySet{}
		snapshot := cedar.ParsedPolicySet{}
		var added []string
		for _, input := range []struct{ id, source string }{{idA, sourceA}, {idB, sourceB}} {
			if !utf8.ValidString(input.id) || !utf8.ValidString(input.source) {
				_, err := rt.ParsePolicy(ctx, input.id, input.source)
				checkNoFault(t, err)
				requireUTF8InputError(t, err)
				continue
			}
			p, err := rt.ParsePolicy(ctx, input.id, input.source)
			checkNoFault(t, err)
			if err != nil {
				continue
			}
			if p.ID() != input.id {
				t.Fatal("parse changed the policy ID")
			}
			q, err := rt.PolicyFromJSON(ctx, p.ID(), p.JSON())
			if err != nil {
				t.Fatal("JSON round trip:", err)
			}
			sameJSON(t, q.JSON(), p.JSON())
			next, err := rt.AddPolicy(ctx, set, p)
			checkNoFault(t, err)
			if err != nil {
				continue
			}
			if _, ok := next.Policy(input.id); !ok {
				t.Fatalf("successful add of %q missing from the set", input.id)
			}
			set, snapshot = next.Source(), next
			added = append(added, input.id)
		}
		next, err := rt.RemovePolicy(ctx, set, removeID)
		checkNoFault(t, err)
		if !utf8.ValidString(removeID) {
			requireUTF8InputError(t, err)
			return
		}
		if err != nil {
			// The set only ever contains successful static adds, so a present
			// ID must be removable.
			if slices.Contains(added, removeID) {
				t.Fatalf("removing static policy %q failed: %v", removeID, err)
			}
		} else {
			if _, ok := next.Policy(removeID); ok {
				t.Fatal("removed policy still present")
			}
			set, snapshot = next.Source(), next
		}
		parsed, err := rt.ParsePolicySet(ctx, set)
		if err != nil {
			t.Fatal("reparsing the edited set:", err)
		}
		sameJSON(t, parsed.JSON(), snapshot.JSON())
		if !slices.Equal(fuzzPolicyIDs(parsed), fuzzPolicyIDs(snapshot)) {
			t.Fatal("reparsed set lists different policies")
		}
	})
}
