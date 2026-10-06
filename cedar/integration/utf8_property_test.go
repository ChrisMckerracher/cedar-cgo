package integration_test

import (
	partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	json "encoding/json"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Valid Unicode never errors at the boundary and marshals without changing
// identity bytes for UIDs, strings, record keys, and nested containers.
func TestPropertyUnicodeValuesPreserveIdentity(t *testing.T) {
	rapid.Check(t, func(pt *rapid.T) {
		TextValue := generator.PropGenUnicode.Draw(pt, "text")
		uid := entityuid.NewEntityUID(TextValue, TextValue)
		values := []any{
			uid, cedarvalue.String(TextValue), cedarvalue.Record{TextValue: cedarvalue.EntityRef(uid)},
			cedarvalue.Set{cedarvalue.EntityRef(uid), cedarvalue.String(TextValue)}, cedarvalue.Decimal(TextValue), cedarvalue.IPAddr(TextValue),
			cedarvalue.Datetime(TextValue), cedarvalue.Duration(TextValue),
			partialinput.KnownEntityUID(uid), partialinput.UnknownEntityUID(TextValue),
			cedarentity.Entity{UID: uid, Parents: []entityuid.EntityUID{uid}, Attrs: cedarvalue.Record{TextValue: cedarvalue.String(TextValue)}},
		}
		for _, value := range values {
			if _, err := json.Marshal(value); err != nil {
				pt.Fatalf("valid text %q rejected for %T: %v", TextValue, value, err)
			}
		}
		var decoded map[string]struct {
			Entity struct{ Type, ID string } `json:"__entity"`
		}
		encoded, err := json.Marshal(cedarvalue.Record{TextValue: cedarvalue.EntityRef(uid)})
		if err != nil {
			pt.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			pt.Fatal(err)
		}
		got, ok := decoded[TextValue]
		if !ok || got.Entity.Type != TextValue || got.Entity.ID != TextValue {
			pt.Fatalf("identity changed: %s", encoded)
		}
	})
}

// Malformed UTF-8 is rejected for every value shape, including nested ones.
func TestPropertyMalformedUTF8ValuesRejected(t *testing.T) {
	rapid.Check(t, func(pt *rapid.T) {
		bad := generator.PropGenMalformed(pt, generator.PropGenUnicode.Draw(pt, "text"))
		uid := entityuid.NewEntityUID("User", bad)
		cases := map[string]any{
			"UID ID":         uid,
			"UID type":       entityuid.NewEntityUID(bad, "a"),
			"string":         cedarvalue.String(bad),
			"extension arg":  cedarvalue.Decimal(bad),
			"record key":     cedarvalue.Record{bad: cedarvalue.Bool(true)},
			"nested set":     cedarvalue.Set{cedarvalue.Record{"a": cedarvalue.Set{cedarvalue.String(bad)}}},
			"entity parents": cedarentity.Entity{UID: entityuid.NewEntityUID("User", "a"), Parents: []entityuid.EntityUID{uid}},
		}
		for name, value := range cases {
			if _, err := json.Marshal(value); err == nil {
				pt.Fatalf("%s: malformed %q encoded without an error", name, bad)
			}
		}
	})
}
