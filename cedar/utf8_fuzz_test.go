package cedar_test

import (
	"encoding/json"
	"testing"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

// Successful encoding must preserve identity bytes and record keys exactly.
func FuzzUTF8Values(f *testing.F) {
	for _, text := range []string{"", "雪😀", "\ufffd", "\x00", "\xff", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		uid := cedar.NewEntityUID(text, text)
		for _, value := range []any{uid, cedar.String(text), cedar.Record{text: cedar.String(text)}, cedar.Set{uid, cedar.String(text)}, cedar.Decimal(text), cedar.IPAddr(text), cedar.Datetime(text), cedar.Duration(text), cedar.KnownEntityUID(uid), cedar.UnknownEntityUID(text)} {
			encoded, err := json.Marshal(value)
			if !utf8.ValidString(text) {
				if err == nil {
					t.Fatalf("malformed identity encoded as %s", encoded)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if !utf8.ValidString(text) {
			return
		}
		encoded, err := json.Marshal(cedar.Record{text: uid})
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]struct {
			Entity struct{ Type, ID string } `json:"__entity"`
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		got, ok := decoded[text]
		if !ok || got.Entity.Type != text || got.Entity.ID != text {
			t.Fatalf("identity changed: %s", encoded)
		}
		encoded, err = json.Marshal(cedar.String(text))
		if err != nil {
			t.Fatal(err)
		}
		var gotText string
		if json.Unmarshal(encoded, &gotText) != nil || gotText != text {
			t.Fatalf("string changed: %s", encoded)
		}
	})
}
