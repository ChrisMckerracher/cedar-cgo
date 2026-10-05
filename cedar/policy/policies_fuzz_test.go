package policy_test

import (
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	time "time"
	utf8 "unicode/utf8"
)

func FuzzPolicySyntax(f *testing.F) {
	fixture := testsupport.LoadPolicyFixture(f)
	seed, _ := json.Marshal(fixture.Constructed.Syntax)
	f.Add(string(seed))
	f.Add(`{"id":"","effect":"permit","principal":{"kind":"any"},"action":{"kind":"in","entities":[]},"resource":{"kind":"any"},"conditions":[{"kind":"when","body":{"Value":9223372036854775807}}]}`)
	rt := testsupport.TestRuntime(f)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 || testsupport.Nesting(input) > testsupport.MaxFuzzNesting {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var syntax cedarpolicy.PolicySyntax
		if json.Unmarshal([]byte(input), &syntax) != nil {
			// Invalid Go syntax envelopes still exercise the Rust policy JSON parser.
			_, err := rt.Policies().PolicyFromJSON(ctx, "fuzz", []byte(input))
			testsupport.CheckNoFault(t, err)
			if !utf8.ValidString(input) {
				testsupport.RequireUTF8InputError(t, err)
			}
			return
		}
		p, err := rt.Policies().PolicyFromSyntax(ctx, syntax)
		testsupport.CheckNoFault(t, err)
		if err != nil {
			return
		}
		if p.ID() != syntax.ID {
			t.Fatal("ID changed")
		}
		q, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON())
		if err != nil {
			t.Fatal("JSON round trip:", err)
		}
		testsupport.SameJSON(t, q.JSON(), p.JSON())
		tree, err := p.Syntax()
		if err != nil {
			t.Fatal(err)
		}
		r, err := rt.Policies().PolicyFromSyntax(ctx, tree)
		if err != nil {
			t.Fatal("PST round trip:", err)
		}
		testsupport.SameJSON(t, r.JSON(), p.JSON())
	})
}
