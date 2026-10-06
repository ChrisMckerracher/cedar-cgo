package integration_test

import (
	json "encoding/json"
	partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testing "testing"
	utf8 "unicode/utf8"
)

// Successful encoding must preserve identity bytes and record keys exactly.
func FuzzUTF8Values(f *testing.F) {
	for _, TextValue := range []string{"", "雪😀", "\ufffd", "\x00", "\xff", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80"} {
		f.Add(TextValue)
	}
	f.Fuzz(func(t *testing.T, TextValue string) {
		uid := entityuid.NewEntityUID(TextValue, TextValue)
		for _, value := range []any{uid, cedarvalue.String(TextValue), cedarvalue.Record{TextValue: cedarvalue.String(TextValue)}, cedarvalue.Set{cedarvalue.EntityRef(uid), cedarvalue.String(TextValue)}, cedarvalue.Decimal(TextValue), cedarvalue.IPAddr(TextValue), cedarvalue.Datetime(TextValue), cedarvalue.Duration(TextValue), partialinput.KnownEntityUID(uid), partialinput.UnknownEntityUID(TextValue)} {
			encoded, err := json.Marshal(value)
			if !utf8.ValidString(TextValue) {
				if err == nil {
					t.Fatalf("malformed identity encoded as %s", encoded)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if !utf8.ValidString(TextValue) {
			return
		}
		encoded, err := json.Marshal(cedarvalue.Record{TextValue: cedarvalue.EntityRef(uid)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]struct {
			Entity struct{ Type, ID string } `json:"__entity"`
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		got, ok := decoded[TextValue]
		if !ok || got.Entity.Type != TextValue || got.Entity.ID != TextValue {
			t.Fatalf("identity changed: %s", encoded)
		}
		encoded, err = json.Marshal(cedarvalue.String(TextValue))
		if err != nil {
			t.Fatal(err)
		}
		var gotText string
		if json.Unmarshal(encoded, &gotText) != nil || gotText != TextValue {
			t.Fatalf("string changed: %s", encoded)
		}
	})
}
