package testsupport

import (
	bytes "bytes"
	json "encoding/json"
	reflect "reflect"
	testing "testing"
)

func AssertSchemaJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b any
	gotDecoder := json.NewDecoder(bytes.NewReader(got))
	gotDecoder.UseNumber()
	if err := gotDecoder.Decode(&a); err != nil {
		t.Fatal(err)
	}
	wantDecoder := json.NewDecoder(bytes.NewReader(want))
	wantDecoder.UseNumber()
	if err := wantDecoder.Decode(&b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("JSON differs\ngot: %s\nwant: %s", got, want)
	}
}
