package generator

import (
	batched "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/batched"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"

	json "encoding/json"
	fmt "fmt"
	rapid "pgregory.net/rapid"
)

// lookup serves exactly the requested UIDs; re-serving across loader rounds
// would be a duplicate-entity error, and omitted UIDs must be marked missing
// or Rust re-requests them until the iteration budget is exhausted.
func (s PropEntityStore) Load(t *rapid.T, uids []entityuid.EntityUID) batched.EntityLoadResult {
	t.Helper()
	out := make([]json.RawMessage, 0, len(uids))
	var missing []entityuid.EntityUID
	for _, uid := range uids {
		if i, ok := s.Index[uid]; ok {
			out = append(out, s.Entries[i])
		} else {
			missing = append(missing, uid)
		}
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return batched.EntityLoadResult{Entities: data, Missing: missing}
}

func (s PropEntityStore) Raw(t *rapid.T) []byte {
	t.Helper()
	data, err := json.Marshal(s.Entries)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// propGenEntityStore returns full snapshots: the Joy entities plus generated
// extras, so policies referencing either namespace resolve to whole entities.
func PropGenEntityStore(joyJSON []byte) *rapid.Generator[PropEntityStore] {
	return rapid.Custom(func(t *rapid.T) PropEntityStore {
		var base []json.RawMessage
		if err := json.Unmarshal(joyJSON, &base); err != nil {
			t.Fatalf("joy entities fixture: %v", err)
		}
		extra, err := json.Marshal(PropGenExtraEntities().Draw(t, "extras"))
		if err != nil {
			t.Fatal(err)
		}
		var appended []json.RawMessage
		if err := json.Unmarshal(extra, &appended); err != nil {
			t.Fatal(err)
		}
		entries := append(base, appended...)
		index := make(map[entityuid.EntityUID]int, len(entries))
		for i, entry := range entries {
			var wire struct {
				UID struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"uid"`
			}
			if err := json.Unmarshal(entry, &wire); err != nil {
				t.Fatalf("entity entry: %v", err)
			}
			index[entityuid.NewEntityUID(wire.UID.Type, wire.UID.ID)] = i
		}
		merged, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		return PropEntityStore{Entities: cedarentity.EntitiesFromJSON(merged), Entries: entries, Index: index}
	})
}

// propGenCondition draws strictly-valid boolean clauses over Joy::Ctx tokens;
// every form mirrors policies the fixture suites already validate.
func PropGenCondition(depth int) *rapid.Generator[string] {
	atoms := []*rapid.Generator[string]{
		rapid.Map(rapid.IntRange(0, 3), func(n int) string { return fmt.Sprintf("context.deviceLevel >= %d", n) }),
		rapid.Map(rapid.IntRange(0, 3), func(n int) string { return fmt.Sprintf("context.deviceLevel < %d", n) }),
		rapid.Just("context.machineAttested"),
		rapid.Just("!context.machineAttested"),
		rapid.Map(rapid.SampledFrom([]string{"ios", "android"}), func(os string) string {
			return fmt.Sprintf("context.platform.os == %q", os)
		}),
		rapid.Map(rapid.IntRange(0, 4), func(n int) string { return fmt.Sprintf("context.platform.securityLevel < %d", n) }),
		rapid.Map(rapid.StringMatching(`s[a-z0-9]{0,4}\*?`), func(p string) string {
			return fmt.Sprintf("context.sessionId like %q", p)
		}),
		rapid.Just("context has deviceLevel"),
		rapid.Just(`context.sourceIp.isInRange(ip("10.0.0.0/8"))`),
		rapid.Just("context.sourceIp.isLoopback()"),
		rapid.Just(`context.now.toTime() >= duration("23h")`),
		rapid.Just(`decimal("1.5").lessThan(decimal("2.0"))`),
		rapid.Map(rapid.SampledFrom(PropJoyDevices), func(id string) string {
			return fmt.Sprintf("principal == Joy::Device::%q", id)
		}),
		rapid.Map(rapid.SampledFrom(PropJoySess), func(id string) string {
			return fmt.Sprintf("resource == Joy::Session::%q", id)
		}),
	}
	if depth <= 0 {
		return rapid.OneOf(atoms...)
	}
	combine := rapid.Custom(func(t *rapid.T) string {
		left := PropGenCondition(depth-1).Draw(t, "left")
		right := PropGenCondition(depth-1).Draw(t, "right")
		op := rapid.SampledFrom([]string{"&&", "||"}).Draw(t, "op")
		if rapid.Bool().Draw(t, "negate") {
			return fmt.Sprintf("!(%s %s %s)", left, op, right)
		}
		return fmt.Sprintf("(%s %s %s)", left, op, right)
	})
	return rapid.OneOf(append(atoms, combine)...)
}
