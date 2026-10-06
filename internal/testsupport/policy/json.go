package policy

import (
	"bytes"
	"encoding/json"
	"testing"

	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
)

func MustPolicyJSON(t testing.TB, p cedarpolicy.ParsedPolicy) map[string]any {
	t.Helper()
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(p.JSON()))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}
