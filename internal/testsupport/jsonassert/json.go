package jsonassert

import (
	bytes "bytes"
	json "encoding/json"
	reflect "reflect"
	testing "testing"
)

func Equal(t testing.TB, got, want []byte) {
	t.Helper()
	if !reflect.DeepEqual(Decode(t, got), Decode(t, want)) {
		t.Fatalf("JSON differs\ngot %s\nwant %s", got, want)
	}
}

func Decode(t testing.TB, data []byte) any {
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
