package testsupport

import (
	json "encoding/json"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	testing "testing"
)

// Keep unique entities with complete ancestry so both evaluation paths use the same data.
func FuzzBatchedStore(t *testing.T, fixture BatchFixture, extraJSON string) (json.RawMessage, map[entityuid.EntityUID]json.RawMessage) {
	t.Helper()
	type entity struct {
		Raw     json.RawMessage
		Uid     BatchUID
		Parents []BatchUID
	}
	parse := func(raw json.RawMessage) (entity, bool) {
		var e struct {
			UID     BatchUID   `json:"uid"`
			Parents []BatchUID `json:"parents"`
		}
		if json.Unmarshal(raw, &e) != nil || e.UID.Type == "" {
			return entity{}, false
		}
		return entity{Raw: raw, Uid: e.UID, Parents: e.Parents}, true
	}
	var pool, extras []entity
	seen := map[entityuid.EntityUID]bool{}
	keep := func(e entity, into *[]entity) bool {
		if seen[e.Uid.Uid()] {
			return false
		}
		seen[e.Uid.Uid()] = true
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
	reachable := map[entityuid.EntityUID]json.RawMessage{}
	for _, e := range pool {
		reachable[e.Uid.Uid()] = e.Raw
	}
	combined := make([]json.RawMessage, 0, len(pool)+len(extras))
	for _, e := range pool {
		combined = append(combined, e.Raw)
	}
	for _, e := range extras {
		closed := true
		for _, p := range e.Parents {
			if _, ok := reachable[p.Uid()]; !ok {
				closed = false
				break
			}
		}
		if !closed {
			continue
		}
		reachable[e.Uid.Uid()] = e.Raw
		combined = append(combined, e.Raw)
	}
	// The index contains exactly the returned store; other requested UIDs are missing.
	data, err := json.Marshal(combined)
	if err != nil {
		t.Fatal(err)
	}
	return data, reachable
}
