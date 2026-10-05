package batched_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	strings "strings"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzBatchedDifferential(f *testing.F) {
	f.Add("alice", "doc", `{}`, `[]`, uint8(0))
	f.Add("alice", "doc", `{"trace":true}`, `[]`, uint8(0))
	f.Add("bob", "doc", `{`, `[{"uid":{"type":"User","id":"carol"},"attrs":{"enabled":false},"parents":[]}]`, uint8(0))
	f.Add("manager", "doc", ``, `[{"uid":{"type":"User","id":"alice"},"attrs":{},"parents":[]}]`, uint8(0))
	f.Add("alice", "doc", `{}`, `[`, uint8(1))
	f.Add("bob", "doc", `{}`, `[{"uid":{"type":"User","id":"bob"},"attrs":{"manager":{"__entity":{"type":"User","id":"missing"}}},"parents":[]}]`, uint8(0))
	fixture := testsupport.BatchedFixtures(f)[0]
	a := testsupport.BatchAuthorizer(f, fixture, testsupport.FuzzLimits)
	rt := testsupport.TestRuntime(f)
	f.Fuzz(func(t *testing.T, principalID, resourceID, ctxJSON, extraJSON string, flags uint8) {
		if len(principalID)+len(resourceID)+len(ctxJSON)+len(extraJSON) > 4096 ||
			testsupport.Nesting(ctxJSON) > 40 || testsupport.Nesting(extraJSON) > 40 {
			t.Skip()
		}
		store, known := testsupport.FuzzBatchedStore(t, fixture, extraJSON)
		req := testsupport.BatchRequest(fixture)
		req.Principal = entityuid.NewEntityUID("User", principalID)
		req.Resource = entityuid.NewEntityUID("Resource", resourceID)
		if json.Valid([]byte(ctxJSON)) {
			req.Context = cedarrequest.ContextFromJSON([]byte(ctxJSON))
		}
		// Only bits 0-2 select a loader behavior; higher bits leave the loader
		// benign, and an adversarial mode only proves anything if Rust called in.
		mode := flags & 7
		called := false
		loader := batched.EntityLoaderFunc(func(_ context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			called = true
			switch {
			case mode&1 != 0:
				return batched.EntityLoadResult{}, errors.New("adversarial loader failure")
			case mode&2 != 0:
				return batched.EntityLoadResult{Entities: json.RawMessage(strings.Repeat("A", 2<<20))}, nil
			case mode&4 != 0:
				return batched.EntityLoadResult{Entities: json.RawMessage(`{"not":"an array"}`)}, nil
			}
			result := batched.EntityLoadResult{}
			entities := make([]json.RawMessage, 0, len(uids))
			for _, uid := range uids {
				if entity, ok := known[uid]; ok {
					entities = append(entities, entity)
				} else {
					result.Missing = append(result.Missing, uid)
				}
			}
			// Cedar keeps prior batches, so return only the requested entities each round.
			var err error
			result.Entities, err = json.Marshal(entities)
			return result, err
		})
		decision, err := a.Batched().AuthorizeBatched(context.Background(), req, loader, batched.BatchedOptions{MaxIterations: 4})
		testsupport.CheckNoFault(t, err)
		// The context gate mirrors the production path: structurally invalid
		// JSON never reaches the wire, so only valid JSON can carry bad bytes.
		if !utf8.ValidString(principalID) || !utf8.ValidString(resourceID) ||
			(json.Valid([]byte(ctxJSON)) && !utf8.ValidString(ctxJSON)) {
			testsupport.RequireUTF8InputError(t, err)
			if decision != cedarrequest.Deny {
				t.Fatalf("malformed request allowed: %s", decision)
			}
			return
		}
		if err != nil && decision != cedarrequest.Deny {
			t.Fatalf("error allowed: %s %v", decision, err)
		}
		if mode != 0 && called {
			if err == nil {
				t.Fatalf("adversarial loader leg unexpectedly succeeded: %v", decision)
			}
			return
		}
		// With identical complete data, batched loading must agree with an
		// ordinary single-shot authorization of the same request.
		schema := cedarschema.SchemaFromCedar(fixture.Schema)
		sequential, seqBuild := rt.NewAuthorizer(context.Background(), authorization.Config{
			Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(fixture.Policies),
			Entities: cedarentity.EntitiesFromJSON(store), Limits: testsupport.FuzzLimits,
		})
		testsupport.CheckNoFault(t, seqBuild)
		if seqBuild != nil {
			return
		}
		response, seqErr := sequential.Authorize(context.Background(), req)
		sequential.Close()
		testsupport.CheckNoFault(t, seqErr)
		if seqErr != nil && response.Decision != cedarrequest.Deny {
			t.Fatalf("error %v came with %v", seqErr, response.Decision)
		}
		if (err == nil) != (seqErr == nil) || (err == nil && decision != response.Decision) {
			t.Fatalf("batched %v/%v disagrees with sequential %v/%v", decision, err, response.Decision, seqErr)
		}
	})
}
