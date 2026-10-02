package cedar_test

import (
	"context"
	"encoding/json"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzBatchedEntities(f *testing.F) {
	for _, seed := range []string{
		`[]`, `[`, `null`, `{}`, `[null]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":true},"parents":[]}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{"manager":{"__entity":{"type":"User","id":"alice"}}},"parents":[]}]`,
	} {
		f.Add([]byte(seed))
	}
	fixture := batchedFixtures(f)[0]
	a := batchAuthorizer(f, fixture, fuzzLimits)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 || nesting(string(data)) > 40 {
			t.Skip()
		}
		decision, err := a.AuthorizeBatched(context.Background(), batchRequest(fixture), cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			return cedar.EntityLoadResult{Entities: json.RawMessage(data)}, nil
		}), cedar.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 8192})
		checkNoFault(t, err)
		if err != nil && decision != cedar.Deny {
			t.Fatalf("error allowed: %s %v", decision, err)
		}
		if err == nil && decision != cedar.Allow && decision != cedar.Deny {
			t.Fatalf("invalid decision %v", decision)
		}
	})
}
