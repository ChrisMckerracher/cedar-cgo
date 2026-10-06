package generator

import (
	bytes "bytes"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	rapid "pgregory.net/rapid"
)

// remarshal preserves exact integer tokens through json.Number.
func PropRemarshal(t *rapid.T, data []byte) []byte {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func PropCheckNoFault(t *rapid.T, err error) {
	t.Helper()
	if errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("module fault: %v", err)
	}
}
