package policy_test

import (
	context "context"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	slices "slices"
	testing "testing"
	time "time"
	utf8 "unicode/utf8"
)

// FuzzPolicyEdits drives add/remove sequences over a parsed policy set and
// requires every operation to either succeed with the inspected membership
// updated, or fail leaving the set coherent and reparseable.
func FuzzPolicyEdits(f *testing.F) {
	f.Add(`permit(principal, action, resource);`, `forbid(principal, action, resource);`, "p0", "p1", "p0")
	f.Add(`permit(principal, action, resource);`, `permit(principal, action, resource) when { 1 + };`, "dup", "dup", "dup")
	f.Add("", "", "", "", "")
	f.Add(`@id("x") permit(principal, action, resource) when { context.a };`, `forbid(principal, action, resource) unless { principal has b };`, "a\n\"雪", "\x00", "missing")
	rt := testruntime.New(f)
	f.Fuzz(func(t *testing.T, sourceA, sourceB, idA, idB, removeID string) {
		if len(sourceA)+len(sourceB)+len(idA)+len(idB)+len(removeID) > 8192 ||
			fuzz.Nesting(sourceA) > fuzz.MaxFuzzNesting || fuzz.Nesting(sourceB) > fuzz.MaxFuzzNesting {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		set := cedarpolicy.PolicySet{}
		snapshot := cedarpolicy.ParsedPolicySet{}
		var added []string
		for _, input := range []struct{ id, source string }{{idA, sourceA}, {idB, sourceB}} {
			if !utf8.ValidString(input.id) || !utf8.ValidString(input.source) {
				_, err := rt.Policies().ParsePolicy(ctx, input.id, input.source)
				fault.CheckNoFault(t, err)
				fault.RequireUTF8InputError(t, err)
				continue
			}
			p, err := rt.Policies().ParsePolicy(ctx, input.id, input.source)
			fault.CheckNoFault(t, err)
			if err != nil {
				continue
			}
			if p.ID() != input.id {
				t.Fatal("parse changed the policy ID")
			}
			q, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON())
			if err != nil {
				t.Fatal("JSON round trip:", err)
			}
			jsonassert.Equal(t, q.JSON(), p.JSON())
			next, err := rt.Policies().AddPolicy(ctx, set, p)
			fault.CheckNoFault(t, err)
			if err != nil {
				continue
			}
			if _, ok := next.Policy(input.id); !ok {
				t.Fatalf("successful add of %q missing from the set", input.id)
			}
			set, snapshot = next.Source(), next
			added = append(added, input.id)
		}
		next, err := rt.Policies().RemovePolicy(ctx, set, removeID)
		fault.CheckNoFault(t, err)
		if !utf8.ValidString(removeID) {
			fault.RequireUTF8InputError(t, err)
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
		parsed, err := rt.Policies().ParsePolicySet(ctx, set)
		if err != nil {
			t.Fatal("reparsing the edited set:", err)
		}
		jsonassert.Equal(t, parsed.JSON(), snapshot.JSON())
		if !slices.Equal(fuzzPolicyIDs(parsed), fuzzPolicyIDs(snapshot)) {
			t.Fatal("reparsed set lists different policies")
		}
	})
}
