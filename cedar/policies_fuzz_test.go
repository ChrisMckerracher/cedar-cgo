package cedar_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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
