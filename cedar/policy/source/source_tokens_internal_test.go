package source

import (
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"

	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"

	reflect "reflect"
	testing "testing"
)

func TestSourceTokenNativeFixtures(t *testing.T) {
	read := func(path string, out any) {
		data, err := fixture.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatal(err)
		}
	}
	var inputs []struct{ Name, Text string }
	var expected []struct {
		Name   string
		Output json.RawMessage
	}
	read("../testdata/parity/source-tokens/input.json", &inputs)
	read("../testdata/parity/source-tokens/expected.json", &expected)
	if len(inputs) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt, err := newRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(context.Background())
	for i, input := range inputs {
		t.Run(input.Name, func(t *testing.T) {
			if input.Name != expected[i].Name {
				t.Fatal("fixture order mismatch")
			}
			want, wantErr := DecodeSourceTokens(expected[i].Output, input.Text)
			got, err := rt.TokenizePolicies(context.Background(), input.Text)
			if wantErr != nil {
				var ce, native *diagnostic.Error
				if !errors.As(wantErr, &native) || !errors.As(err, &ce) || !reflect.DeepEqual(got, SourceTokens{}) || ce.Kind != native.Kind || ce.Message != native.Message {
					t.Fatalf("got %+v %v; native %+v %v", got, err, want, wantErr)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v %v; native %+v", got, err, want)
			}
		})
	}
}

func TestMalformedSourceTokenResponses(t *testing.T) {
	for _, data := range []string{
		``, `null`, `{}`, `{"tokens":[],"trailing_comments":null}`,
		`{"tokens":[{"kind":"","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":1,"end":0},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":3},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":null,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":null},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":null,"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":-1,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":4294967296},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"wrong","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":1},"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""},{"kind":"identifier","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
	} {
		got, err := DecodeSourceTokens([]byte(data), "x")
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault || !reflect.DeepEqual(got, SourceTokens{}) {
			t.Fatalf("accepted malformed response %s: %+v %v", data, got, err)
		}
	}
	data := []byte(`{"tokens":[{"kind":"string","text":"雪","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`)
	if _, err := DecodeSourceTokens(data, "雪"); err == nil {
		t.Fatal("accepted a span that splits UTF-8")
	}
}

func TestSourceTokenZeroStartResponse(t *testing.T) {
	data := []byte(`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`)
	result, err := DecodeSourceTokens(data, "x")
	if err != nil || len(result.Tokens) != 1 || result.Tokens[0].Span != (TokenSpan{Start: 0, End: 1}) {
		t.Fatalf("rejected an explicit zero offset: %+v %v", result, err)
	}
}
