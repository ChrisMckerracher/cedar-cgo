package policy_test

import (
	"context"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"

	"testing"
)

func checkNativePolicyParses(t *testing.T, rt *cedar.Runtime, f PolicyFixture) {
	ctx := context.Background()
	for _, tc := range f.Parses {
		t.Run("parse/"+tc.ID, func(t *testing.T) {
			p, err := rt.Policies().ParsePolicy(ctx, tc.ID, tc.Source)
			PolicyErrorMatches(t, err, tc.Error)
			if err != nil {
				return
			}
			if p.ID() != tc.ID {
				t.Fatalf("ID %q != %q", p.ID(), tc.ID)
			}
			jsonassert.Equal(t, p.JSON(), tc.JSON)
			q, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON())
			if err != nil {
				t.Fatal(err)
			}
			jsonassert.Equal(t, q.JSON(), p.JSON())
			// The independent PST oracle retains its normalized JSON and rendered source.
			q, err = rt.Policies().PolicyFromJSON(ctx, p.ID(), tc.PSTJSON)
			if err != nil {
				t.Fatal(err)
			}
			if q.ID() != p.ID() {
				t.Fatal("PST lost ID")
			}
			jsonassert.Equal(t, q.JSON(), tc.PSTJSON)
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
			jsonassert.Equal(t, round.JSON(), tc.RenderedJSON)
		})
	}
}
