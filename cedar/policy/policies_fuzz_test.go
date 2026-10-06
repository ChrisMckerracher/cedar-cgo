package policy_test

import (
	context "context"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
	time "time"
	utf8 "unicode/utf8"
)

// The historical target name now exercises Cedar's documented JSON policy representation.
func FuzzPolicySyntax(f *testing.F) {
	fixture := LoadPolicyFixture(f)
	f.Add(fixture.Constructed.Syntax.ID, string(fixture.Constructed.JSON))
	f.Add("", `{"effect":"permit","principal":{"op":"All"},"action":{"op":"in","entities":[]},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"Value":9223372036854775807}}]}`)
	f.Add("quote\"\nslash\\雪", string(fixture.Constructed.JSON))
	rt := testruntime.New(f)
	f.Fuzz(func(t *testing.T, id, input string) {
		if len(id)+len(input) > 64<<10 || fuzz.Nesting(input) > fuzz.MaxFuzzNesting {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p, err := rt.Policies().PolicyFromJSON(ctx, id, []byte(input))
		fault.CheckNoFault(t, err)
		if !utf8.ValidString(id) || !utf8.ValidString(input) {
			fault.RequireUTF8InputError(t, err)
		}
		if err != nil {
			return
		}
		if p.ID() != id {
			t.Fatal("ID changed")
		}
		q, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON())
		if err != nil {
			t.Fatal("JSON round trip:", err)
		}
		jsonassert.Equal(t, q.JSON(), p.JSON())
		cedar, err := p.Cedar()
		if err != nil {
			t.Fatal(err)
		}
		r, err := rt.Policies().ParsePolicy(ctx, p.ID(), cedar)
		if err != nil {
			t.Fatal("Cedar round trip:", err)
		}
		// Cedar text combines clauses; its normalized projection must remain stable.
		text, err := r.Cedar()
		if err != nil {
			t.Fatal(err)
		}
		s, err := rt.Policies().ParsePolicy(ctx, r.ID(), text)
		if err != nil {
			t.Fatal(err)
		}
		jsonassert.Equal(t, s.JSON(), r.JSON())
	})
}
