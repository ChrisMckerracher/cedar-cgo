package execution

import (
	"bytes"
	jsonv1 "encoding/json"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
)

func TestEncodePreservesRawStringsAndEscaping(t *testing.T) {
	input := struct {
		Raw jsonv1.RawMessage `json:"raw"`
	}{jsonv1.RawMessage(`{"escaped":"\u0041\n\u003c\ud83d\ude00","literal":"<&>` + "\u2028\u2029" + `","maximum":9223372036854775807}`)}
	want, err := jsonv1.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Encode(input, "input", len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded bytes changed: got %s, want %s", got, want)
	}
	if _, err := Encode(input, "input", len(want)-1); err == nil {
		t.Fatal("encoded-byte limit did not reject the complete envelope")
	}
}

func TestEncodePreservedRawStringsRemainStrict(t *testing.T) {
	inputs := []jsonv1.RawMessage{
		jsonv1.RawMessage(`{"a":1,"a":2}`),
		jsonv1.RawMessage(`{"a":1,"\u0061":2}`),
		jsonv1.RawMessage(`{"value":"\ud800"}`),
		jsonv1.RawMessage(`{"value":"\udc00"}`),
		jsonv1.RawMessage(`{"value":"\ud800\u0041"}`),
		jsonv1.RawMessage("{\"value\":\"\x00\"}"),
		jsonv1.RawMessage("{\"value\":\"\xff\"}"),
		jsonv1.RawMessage(`{} {}`),
	}
	for _, input := range inputs {
		t.Run(string(input), func(t *testing.T) {
			got, err := Encode(input, "input", 1<<20)
			var inputError *diagnostic.Error
			if len(got) != 0 || !errors.As(err, &inputError) || inputError.Kind != diagnostic.KindInput {
				t.Fatalf("invalid input delivered a result: got %q, error %v", got, err)
			}
		})
	}
}
