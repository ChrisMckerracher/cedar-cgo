package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzPartialEntities(f *testing.F) {
	for _, seed := range []string{
		`[]`, `[`, `null`, `{}`, `[{"uid":{"type":"User","id":"alice"}}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{},"parents":[],"tags":{}}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{"nested":{"__entity":{"type":"User","id":"bob"}}}}]`,
	} {
		f.Add([]byte(seed))
	}
	a := partialAuthorizer(f, cedar.Limits{MaxInstances: 1, MaxRequestBytes: 32 << 10, CallTimeout: fuzzLimits.CallTimeout})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<10 || nesting(string(data)) > 40 {
			t.Skip()
		}
		req := partialRequest()
		req.Entities = cedar.PartialEntitiesFromJSON(data)
		r, err := a.PartialAuthorize(context.Background(), req)
		checkNoFault(t, err)
		if err != nil {
			if r.Decision != cedar.Undecided {
				t.Fatalf("error grants decision: %+v %v", r, err)
			}
			return
		}
		if r.Decision != cedar.Undecided {
			t.Fatalf("unknown MFA unexpectedly decided: %+v", r)
		}
	})
}
