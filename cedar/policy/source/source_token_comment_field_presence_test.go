package source

import (
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	reflect "reflect"
	strings "strings"
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

func TestSourceTokenResponseLexicalContract(t *testing.T) {
	for _, tc := range []struct {
		name, source, message string
		tokens                []SourceToken
	}{
		{name: "omitted all tokens", source: "x", message: "nontrivia"},
		{name: "omitted prefix", source: "y x", message: "nontrivia", tokens: []SourceToken{SourceTokenForTest("identifier", "x", 2)}},
		{name: "omitted middle", source: "x y z", message: "nontrivia", tokens: []SourceToken{SourceTokenForTest("identifier", "x", 0), SourceTokenForTest("identifier", "z", 4)}},
		{name: "omitted suffix", source: "x y", message: "nontrivia", tokens: []SourceToken{SourceTokenForTest("identifier", "x", 0)}},
		{name: "token inside comment", source: "// x", message: "nontrivia", tokens: []SourceToken{SourceTokenForTest("identifier", "x", 3)}},
		{name: "block comment is not trivia", source: "/* x */", message: "nontrivia"},
		{name: "zero width space is not trivia", source: "\u200b", message: "nontrivia"},
		{name: "number kind on identifier", source: "x", message: "spelling", tokens: []SourceToken{SourceTokenForTest("number", "x", 0)}},
		{name: "string kind on identifier", source: "x", message: "spelling", tokens: []SourceToken{SourceTokenForTest("string", "x", 0)}},
		{name: "identifier kind on keyword", source: "permit", message: "spelling", tokens: []SourceToken{SourceTokenForTest("identifier", "permit", 0)}},
		{name: "identifier starts with digit", source: "1x", message: "spelling", tokens: []SourceToken{SourceTokenForTest("identifier", "1x", 0)}},
		{name: "identifier uses unicode", source: "雪", message: "spelling", tokens: []SourceToken{SourceTokenForTest("identifier", "雪", 0)}},
		{name: "number contains punctuation", source: "1.0", message: "spelling", tokens: []SourceToken{SourceTokenForTest("number", "1.0", 0)}},
		{name: "unterminated string", source: `"x`, message: "spelling", tokens: []SourceToken{SourceTokenForTest("string", `"x`, 0)}},
		{name: "unescaped quote", source: `"a"b"`, message: "spelling", tokens: []SourceToken{SourceTokenForTest("string", `"a"b"`, 0)}},
		{name: "escaped line feed", source: "\"a\\\nb\"", message: "spelling", tokens: []SourceToken{SourceTokenForTest("string", "\"a\\\nb\"", 0)}},
		{name: "split identifier", source: "xy", message: "spelling", tokens: []SourceToken{SourceTokenForTest("identifier", "x", 0), SourceTokenForTest("identifier", "y", 1)}},
		{name: "split number", source: "12", message: "spelling", tokens: []SourceToken{SourceTokenForTest("number", "1", 0), SourceTokenForTest("number", "2", 1)}},
		{name: "keyword prefix", source: "permitx", message: "spelling", tokens: []SourceToken{SourceTokenForTest("permit", "permit", 0), SourceTokenForTest("identifier", "x", 6)}},
		{name: "split operator", source: "::", message: "spelling", tokens: []SourceToken{SourceTokenForTest(":", ":", 0), SourceTokenForTest(":", ":", 1)}},
		{name: "comment marker as tokens", source: "//", message: "spelling", tokens: []SourceToken{SourceTokenForTest("/", "/", 0), SourceTokenForTest("/", "/", 1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeSourceTokens(SourceTokenResponseForTest(t, tc.tokens, nil), tc.source)
			var ce *diagnostic.Error
			if !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault || !strings.Contains(ce.Message, tc.message) || !reflect.DeepEqual(got, SourceTokens{}) {
				t.Fatalf("wrong lexical contract result: %+v %v", got, err)
			}
		})
	}
}
