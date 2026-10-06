package batched_test

import (
	context "context"
	json "encoding/json"
	batched "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/batched"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"

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
	fixture := BatchedFixtures(f)[0]
	a := BatchAuthorizer(f, fixture, fuzz.FuzzLimits)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 || fuzz.Nesting(string(data)) > 40 {
			t.Skip()
		}
		decision, err := a.Batched().AuthorizeBatched(context.Background(), BatchRequest(fixture), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return batched.EntityLoadResult{Entities: json.RawMessage(data)}, nil
		}), batched.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 8192})
		fault.CheckNoFault(t, err)
		if !utf8.Valid(data) {
			fault.RequireUTF8InputError(t, err)
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
