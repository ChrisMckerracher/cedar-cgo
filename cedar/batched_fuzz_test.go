package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// Keep unique entities with complete ancestry so both evaluation paths use the same data.
func fuzzBatchedStore(t *testing.T, fixture batchFixture, extraJSON string) (json.RawMessage, map[cedar.EntityUID]json.RawMessage) {
	t.Helper()
	type entity struct {
		raw     json.RawMessage
		uid     batchUID
		parents []batchUID
	}
	parse := func(raw json.RawMessage) (entity, bool) {
		var e struct {
			UID     batchUID   `json:"uid"`
			Parents []batchUID `json:"parents"`
		}
		if json.Unmarshal(raw, &e) != nil || e.UID.Type == "" {
			return entity{}, false
		}
		return entity{raw: raw, uid: e.UID, parents: e.Parents}, true
	}
	var pool, extras []entity
	seen := map[cedar.EntityUID]bool{}
	keep := func(e entity, into *[]entity) bool {
		if seen[e.uid.uid()] {
			return false
		}
		seen[e.uid.uid()] = true
		*into = append(*into, e)
		return true
	}
	for _, batch := range fixture.Batches {
		var raws []json.RawMessage
		if json.Unmarshal(batch.Entities, &raws) == nil {
			for _, raw := range raws {
				if e, ok := parse(raw); ok {
					keep(e, &pool)
				}
			}
		}
	}
	var raws []json.RawMessage
	if json.Unmarshal([]byte(extraJSON), &raws) == nil {
		for _, raw := range raws {
			if e, ok := parse(raw); ok {
				keep(e, &extras)
			}
		}
	}
	reachable := map[cedar.EntityUID]json.RawMessage{}
	for _, e := range pool {
		reachable[e.uid.uid()] = e.raw
	}
	combined := make([]json.RawMessage, 0, len(pool)+len(extras))
	for _, e := range pool {
		combined = append(combined, e.raw)
	}
	for _, e := range extras {
		closed := true
		for _, p := range e.parents {
			if _, ok := reachable[p.uid()]; !ok {
				closed = false
				break
			}
		}
		if !closed {
			continue
		}
		reachable[e.uid.uid()] = e.raw
		combined = append(combined, e.raw)
	}
	// The index contains exactly the returned store; other requested UIDs are missing.
	data, err := json.Marshal(combined)
	if err != nil {
		t.Fatal(err)
	}
	return data, reachable
}

func FuzzBatchedDifferential(f *testing.F) {
	f.Add("alice", "doc", `{}`, `[]`, uint8(0))
	f.Add("alice", "doc", `{"trace":true}`, `[]`, uint8(0))
	f.Add("bob", "doc", `{`, `[{"uid":{"type":"User","id":"carol"},"attrs":{"enabled":false},"parents":[]}]`, uint8(0))
	f.Add("manager", "doc", ``, `[{"uid":{"type":"User","id":"alice"},"attrs":{},"parents":[]}]`, uint8(0))
	f.Add("alice", "doc", `{}`, `[`, uint8(1))
	f.Add("bob", "doc", `{}`, `[{"uid":{"type":"User","id":"bob"},"attrs":{"manager":{"__entity":{"type":"User","id":"missing"}}},"parents":[]}]`, uint8(0))
	fixture := batchedFixtures(f)[0]
	a := batchAuthorizer(f, fixture, fuzzLimits)
	rt := testRuntime(f)
	f.Fuzz(func(t *testing.T, principalID, resourceID, ctxJSON, extraJSON string, flags uint8) {
		if len(principalID)+len(resourceID)+len(ctxJSON)+len(extraJSON) > 4096 ||
			nesting(ctxJSON) > 40 || nesting(extraJSON) > 40 {
			t.Skip()
		}
		store, known := fuzzBatchedStore(t, fixture, extraJSON)
		req := batchRequest(fixture)
		req.Principal = cedar.NewEntityUID("User", principalID)
		req.Resource = cedar.NewEntityUID("Resource", resourceID)
		if json.Valid([]byte(ctxJSON)) {
			req.Context = cedar.ContextFromJSON([]byte(ctxJSON))
		}
		// Only bits 0-2 select a loader behavior; higher bits leave the loader
		// benign, and an adversarial mode only proves anything if Rust called in.
		mode := flags & 7
		called := false
		loader := cedar.EntityLoaderFunc(func(_ context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			called = true
			switch {
			case mode&1 != 0:
				return cedar.EntityLoadResult{}, errors.New("adversarial loader failure")
			case mode&2 != 0:
				return cedar.EntityLoadResult{Entities: json.RawMessage(strings.Repeat("A", 2<<20))}, nil
			case mode&4 != 0:
				return cedar.EntityLoadResult{Entities: json.RawMessage(`{"not":"an array"}`)}, nil
			}
			result := cedar.EntityLoadResult{}
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
		decision, err := a.AuthorizeBatched(context.Background(), req, loader, cedar.BatchedOptions{MaxIterations: 4})
		checkNoFault(t, err)
		if err != nil && decision != cedar.Deny {
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
		schema := cedar.SchemaFromCedar(fixture.Schema)
		sequential, seqBuild := rt.NewAuthorizer(context.Background(), cedar.Config{
			Schema: &schema, Policies: cedar.PoliciesFromCedar(fixture.Policies),
			Entities: cedar.EntitiesFromJSON(store), Limits: fuzzLimits,
		})
		checkNoFault(t, seqBuild)
		if seqBuild != nil {
			return
		}
		response, seqErr := sequential.Authorize(context.Background(), req)
		sequential.Close()
		checkNoFault(t, seqErr)
		if seqErr != nil && response.Decision != cedar.Deny {
			t.Fatalf("error %v came with %v", seqErr, response.Decision)
		}
		if (err == nil) != (seqErr == nil) || (err == nil && decision != response.Decision) {
			t.Fatalf("batched %v/%v disagrees with sequential %v/%v", decision, err, response.Decision, seqErr)
		}
	})
}
