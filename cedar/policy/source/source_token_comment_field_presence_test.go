package source

import (
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	reflect "reflect"
	testing "testing"
)

func TestSourceTokenCommentFieldPresence(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       any
		remove      bool
		final       bool
	}{
		{name: "missing trailing", field: "trailing_comment", remove: true},
		{name: "null trailing", field: "trailing_comment"},
		{name: "missing leading", field: "leading_comments", remove: true},
		{name: "null leading", field: "leading_comments"},
		{name: "null leading entry", field: "leading_comments", value: []any{nil}},
		{name: "nonstring leading entry", field: "leading_comments", value: []any{1}},
		{name: "missing final", field: "trailing_comments", remove: true, final: true},
		{name: "null final", field: "trailing_comments", final: true},
		{name: "null final entry", field: "trailing_comments", value: []any{nil}, final: true},
		{name: "nonstring final entry", field: "trailing_comments", value: []any{1}, final: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := map[string]any{
				"kind": "identifier", "text": "x", "span": TokenSpan{Start: 0, End: 1},
				"leading_comments": []string{}, "trailing_comment": "",
			}
			response := map[string]any{"tokens": []any{token}, "trailing_comments": []string{}}
			data, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeSourceTokens(data, "x"); err != nil {
				t.Fatalf("valid baseline failed: %v", err)
			}
			fields := token
			if tc.final {
				fields = response
			}
			if tc.remove {
				delete(fields, tc.field)
			} else {
				fields[tc.field] = tc.value
			}
			data, err = json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeSourceTokens(data, "x")
			var ce *diagnostic.Error
			if !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault || !reflect.DeepEqual(got, SourceTokens{}) {
				t.Fatalf("accepted malformed comment field: %s; %+v %v", data, got, err)
			}
		})
	}
}

func SourceTokenForTest(kind, TextValue string, start uint32) SourceToken {
	return SourceToken{Kind: kind, Text: TextValue, Span: TokenSpan{Start: start, End: start + uint32(len(TextValue))}, LeadingComments: []string{}}
}

func SourceTokenResponseForTest(t *testing.T, tokens []SourceToken, comments []string) []byte {
	t.Helper()
	if tokens == nil {
		tokens = []SourceToken{}
	}
	if comments == nil {
		comments = []string{}
	}
	data, err := json.Marshal(SourceTokens{Tokens: tokens, TrailingComments: comments})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
