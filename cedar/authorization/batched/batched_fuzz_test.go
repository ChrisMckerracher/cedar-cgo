package batched_test

import (
	context "context"
	json "encoding/json"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzBatchedEntities(f *testing.F) {
	for _, seed := range []string{
		`[]`, `[`, `null`, `{}`, `[null]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":true},"parents":[]}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{"manager":{"__entity":{"type":"User","id":"alice"}}},"parents":[]}]`,
	} {
		f.Add([]byte(seed))
	}
	fixture := testsupport.BatchedFixtures(f)[0]
	a := testsupport.BatchAuthorizer(f, fixture, testsupport.FuzzLimits)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 || testsupport.Nesting(string(data)) > 40 {
			t.Skip()
		}
		decision, err := a.Batched().AuthorizeBatched(context.Background(), testsupport.BatchRequest(fixture), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return batched.EntityLoadResult{Entities: json.RawMessage(data)}, nil
		}), batched.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 8192})
		testsupport.CheckNoFault(t, err)
		if !utf8.Valid(data) {
			testsupport.RequireUTF8InputError(t, err)
			if decision != cedarrequest.Deny {
				t.Fatalf("malformed loader result allowed: %s", decision)
			}
			return
		}
		if err != nil && decision != cedarrequest.Deny {
			t.Fatalf("error allowed: %s %v", decision, err)
		}
		if err == nil && decision != cedarrequest.Allow && decision != cedarrequest.Deny {
			t.Fatalf("invalid decision %v", decision)
		}
	})
}
