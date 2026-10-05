package policy_test

import (
	"context"
	"encoding/json"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	"testing"
)

func checkNativePolicyParses(t *testing.T, rt *cedar.Runtime, f testsupport.PolicyFixture) {
	ctx := context.Background()
	for _, tc := range f.Parses {
		t.Run("parse/"+tc.ID, func(t *testing.T) {
			p, err := rt.Policies().ParsePolicy(ctx, tc.ID, tc.Source)
			testsupport.PolicyErrorMatches(t, err, tc.Error)
			if err != nil {
				return
			}
			if p.ID() != tc.ID {
				t.Fatalf("ID %q != %q", p.ID(), tc.ID)
			}
			testsupport.SameJSON(t, p.JSON(), tc.JSON)
			q, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON())
			if err != nil {
				t.Fatal(err)
			}
			testsupport.SameJSON(t, q.JSON(), p.JSON())
			syntax, err := p.Syntax()
			if err != nil {
				t.Fatal(err)
			}
			q, err = rt.Policies().PolicyFromSyntax(ctx, syntax)
			if err != nil {
				t.Fatal(err)
			}
			if q.ID() != p.ID() {
				t.Fatal("PST lost ID")
			}
			testsupport.SameJSON(t, q.JSON(), tc.PSTJSON)
			// PST normalizes valueless/empty annotations; compare its own stable projection.
			syntax2, err := q.Syntax()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(syntax)
			c, _ := json.Marshal(syntax2)
			testsupport.SameJSON(t, b, c)
			cedarText, err := q.Cedar()
			if err != nil {
				t.Fatal(err)
			}
			if cedarText != tc.PSTCedar {
				t.Fatalf("PST Cedar differs: %q vs %q", cedarText, tc.PSTCedar)
			}
			round, err := rt.Policies().ParsePolicy(ctx, p.ID(), cedarText)
			if err != nil {
				t.Fatal(err)
			}
			testsupport.SameJSON(t, round.JSON(), tc.RenderedJSON)
		})
	}
}
