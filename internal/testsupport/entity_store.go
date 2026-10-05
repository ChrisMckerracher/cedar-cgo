package testsupport

import (
	bytes "bytes"
	json "encoding/json"
	reflect "reflect"
	testing "testing"
)

func EqualJSON(t testing.TB, got, want []byte) {
	t.Helper()
	if !reflect.DeepEqual(EntityStoreJSON(t, got), EntityStoreJSON(t, want)) {
		t.Fatalf("JSON differs\ngot %s\nwant %s", got, want)
	}
}

func EntityStoreJSON(t testing.TB, data []byte) any {
	t.Helper()
	if !json.Valid(data) {
		t.Fatalf("invalid JSON: %s", data)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
