package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSourceTokenNativeFixtures(t *testing.T) {
	read := func(path string, out any) {
		data, err := os.ReadFile(path)
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
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	for i, input := range inputs {
		t.Run(input.Name, func(t *testing.T) {
			if input.Name != expected[i].Name {
				t.Fatal("fixture order mismatch")
			}
			want, wantErr := decodeSourceTokens(expected[i].Output, input.Text)
			got, err := rt.TokenizePolicies(context.Background(), input.Text)
			if wantErr != nil {
				var ce, native *Error
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
		`{"tokens":[{"kind":"unknown","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
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
		`{"tokens":[{"kind":"permit","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":1},"trailing_comment":""}],"trailing_comments":[]}`,
		`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""},{"kind":"identifier","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`,
	} {
		got, err := decodeSourceTokens([]byte(data), "x")
		var ce *Error
		if !errors.As(err, &ce) || ce.Kind != KindFault || !reflect.DeepEqual(got, SourceTokens{}) {
			t.Fatalf("accepted malformed response %s: %+v %v", data, got, err)
		}
	}
	data := []byte(`{"tokens":[{"kind":"string","text":"雪","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`)
	if _, err := decodeSourceTokens(data, "雪"); err == nil {
		t.Fatal("accepted a span that splits UTF-8")
	}
}

func TestSourceTokenZeroStartResponse(t *testing.T) {
	data := []byte(`{"tokens":[{"kind":"identifier","text":"x","span":{"start":0,"end":1},"leading_comments":[],"trailing_comment":""}],"trailing_comments":[]}`)
	result, err := decodeSourceTokens(data, "x")
	if err != nil || len(result.Tokens) != 1 || result.Tokens[0].Span != (TokenSpan{Start: 0, End: 1}) {
		t.Fatalf("rejected an explicit zero offset: %+v %v", result, err)
	}
}

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
			if _, err := decodeSourceTokens(data, "x"); err != nil {
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
			got, err := decodeSourceTokens(data, "x")
			var ce *Error
			if !errors.As(err, &ce) || ce.Kind != KindFault || !reflect.DeepEqual(got, SourceTokens{}) {
				t.Fatalf("accepted malformed comment field: %s; %+v %v", data, got, err)
			}
		})
	}
}

func sourceTokenForTest(kind, text string, start uint32) SourceToken {
	return SourceToken{Kind: kind, Text: text, Span: TokenSpan{Start: start, End: start + uint32(len(text))}, LeadingComments: []string{}}
}

func sourceTokenResponseForTest(t *testing.T, tokens []SourceToken, comments []string) []byte {
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
		{name: "omitted prefix", source: "y x", message: "nontrivia", tokens: []SourceToken{sourceTokenForTest("identifier", "x", 2)}},
		{name: "omitted middle", source: "x y z", message: "nontrivia", tokens: []SourceToken{sourceTokenForTest("identifier", "x", 0), sourceTokenForTest("identifier", "z", 4)}},
		{name: "omitted suffix", source: "x y", message: "nontrivia", tokens: []SourceToken{sourceTokenForTest("identifier", "x", 0)}},
		{name: "token inside comment", source: "// x", message: "nontrivia", tokens: []SourceToken{sourceTokenForTest("identifier", "x", 3)}},
		{name: "block comment is not trivia", source: "/* x */", message: "nontrivia"},
		{name: "zero width space is not trivia", source: "\u200b", message: "nontrivia"},
		{name: "number kind on identifier", source: "x", message: "spelling", tokens: []SourceToken{sourceTokenForTest("number", "x", 0)}},
		{name: "string kind on identifier", source: "x", message: "spelling", tokens: []SourceToken{sourceTokenForTest("string", "x", 0)}},
		{name: "identifier kind on keyword", source: "permit", message: "spelling", tokens: []SourceToken{sourceTokenForTest("identifier", "permit", 0)}},
		{name: "identifier starts with digit", source: "1x", message: "spelling", tokens: []SourceToken{sourceTokenForTest("identifier", "1x", 0)}},
		{name: "identifier uses unicode", source: "雪", message: "spelling", tokens: []SourceToken{sourceTokenForTest("identifier", "雪", 0)}},
		{name: "number contains punctuation", source: "1.0", message: "spelling", tokens: []SourceToken{sourceTokenForTest("number", "1.0", 0)}},
		{name: "unterminated string", source: `"x`, message: "spelling", tokens: []SourceToken{sourceTokenForTest("string", `"x`, 0)}},
		{name: "unescaped quote", source: `"a"b"`, message: "spelling", tokens: []SourceToken{sourceTokenForTest("string", `"a"b"`, 0)}},
		{name: "escaped line feed", source: "\"a\\\nb\"", message: "spelling", tokens: []SourceToken{sourceTokenForTest("string", "\"a\\\nb\"", 0)}},
		{name: "split identifier", source: "xy", message: "spelling", tokens: []SourceToken{sourceTokenForTest("identifier", "x", 0), sourceTokenForTest("identifier", "y", 1)}},
		{name: "split number", source: "12", message: "spelling", tokens: []SourceToken{sourceTokenForTest("number", "1", 0), sourceTokenForTest("number", "2", 1)}},
		{name: "keyword prefix", source: "permitx", message: "spelling", tokens: []SourceToken{sourceTokenForTest("permit", "permit", 0), sourceTokenForTest("identifier", "x", 6)}},
		{name: "split operator", source: "::", message: "spelling", tokens: []SourceToken{sourceTokenForTest(":", ":", 0), sourceTokenForTest(":", ":", 1)}},
		{name: "comment marker as tokens", source: "//", message: "spelling", tokens: []SourceToken{sourceTokenForTest("/", "/", 0), sourceTokenForTest("/", "/", 1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSourceTokens(sourceTokenResponseForTest(t, tc.tokens, nil), tc.source)
			var ce *Error
			if !errors.As(err, &ce) || ce.Kind != KindFault || !strings.Contains(ce.Message, tc.message) || !reflect.DeepEqual(got, SourceTokens{}) {
				t.Fatalf("wrong lexical contract result: %+v %v", got, err)
			}
		})
	}
}

func TestSourceTokenNativeSpellingAndTrivia(t *testing.T) {
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	word := sourceTokenForTest("identifier", "x", 0)
	word.TrailingComment = "// first\r// second"
	for _, tc := range []struct {
		name, source string
		tokens       []SourceToken
		comments     []string
	}{
		{name: "empty"},
		{name: "unicode whitespace", source: "\t\r\n\v\f \u0085\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000"},
		{name: "comment only", source: " // one\r// two\u2028part  \n", comments: []string{"// one", "// two\u2028part"}},
		{name: "keyword", source: "permit", tokens: []SourceToken{sourceTokenForTest("permit", "permit", 0)}},
		{name: "generic kind name is an identifier", source: "number", tokens: []SourceToken{sourceTokenForTest("identifier", "number", 0)}},
		{name: "large lexical number", source: "123456789012345678901234567890", tokens: []SourceToken{sourceTokenForTest("number", "123456789012345678901234567890", 0)}},
		{name: "adjacent number and identifier", source: "123abc", tokens: []SourceToken{sourceTokenForTest("number", "123", 0), sourceTokenForTest("identifier", "abc", 3)}},
		{name: "adjacent slot and identifier", source: "?principality", tokens: []SourceToken{sourceTokenForTest("?principal", "?principal", 0), sourceTokenForTest("identifier", "ity", 10)}},
		{name: "adjacent operator tokens", source: "!<=>>=::::/+-**", tokens: []SourceToken{
			sourceTokenForTest("!", "!", 0), sourceTokenForTest("<=", "<=", 1), sourceTokenForTest(">", ">", 3),
			sourceTokenForTest(">=", ">=", 4), sourceTokenForTest("::", "::", 6), sourceTokenForTest("::", "::", 8),
			sourceTokenForTest("/", "/", 10), sourceTokenForTest("+", "+", 11), sourceTokenForTest("-", "-", 12),
			sourceTokenForTest("*", "*", 13), sourceTokenForTest("*", "*", 14),
		}},
		{name: "adjacent string tokens", source: `"a""b"`, tokens: []SourceToken{sourceTokenForTest("string", `"a"`, 0), sourceTokenForTest("string", `"b"`, 3)}},
		{name: "raw line break in string", source: "\"a\nb\"", tokens: []SourceToken{sourceTokenForTest("string", "\"a\nb\"", 0)}},
		{name: "unsupported semantic escape", source: `"a\q"`, tokens: []SourceToken{sourceTokenForTest("string", `"a\q"`, 0)}},
		{name: "escaped carriage return", source: "\"a\\\rb\"", tokens: []SourceToken{sourceTokenForTest("string", "\"a\\\rb\"", 0)}},
		{name: "lone carriage return gap", source: "x// first\r// second\ry", tokens: []SourceToken{word, sourceTokenForTest("identifier", "y", uint32(len("x// first\r// second\r")))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := decodeSourceTokens(sourceTokenResponseForTest(t, tc.tokens, tc.comments), tc.source)
			if err != nil {
				t.Fatalf("rejected native lexical form: %v", err)
			}
			got, err := rt.TokenizePolicies(context.Background(), tc.source)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("native lexer differs: %+v %v; expected %+v", got, err, want)
			}
		})
	}
	for _, source := range []string{"\"a\\\nb\"", `"unterminated`} {
		got, err := rt.TokenizePolicies(context.Background(), source)
		var ce *Error
		if !errors.As(err, &ce) || ce.Kind != KindPolicies || !reflect.DeepEqual(got, SourceTokens{}) {
			t.Fatalf("native lexer accepted an invalid string: %q; %+v %v", source, got, err)
		}
	}
}

func TestSourceTokenCommentAttachment(t *testing.T) {
	for _, tc := range []struct {
		name, source, message string
		token                 SourceToken
		comments              []string
	}{
		{name: "wrong leading summary", source: "// leading  \nx", message: "leading comments", token: SourceToken{Kind: "identifier", Text: "x", Span: TokenSpan{Start: 13, End: 14}, LeadingComments: []string{"// leading  "}}},
		{name: "wrong trailing summary", source: "x// trailing", message: "trailing comment", token: sourceTokenForTest("identifier", "x", 0)},
		{name: "wrong final summary", source: "x\n// final", message: "final comments", token: sourceTokenForTest("identifier", "x", 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSourceTokens(sourceTokenResponseForTest(t, []SourceToken{tc.token}, tc.comments), tc.source)
			var ce *Error
			if !errors.As(err, &ce) || ce.Kind != KindFault || !strings.Contains(ce.Message, tc.message) || !reflect.DeepEqual(got, SourceTokens{}) {
				t.Fatalf("wrong comment attachment result: %+v %v", got, err)
			}
		})
	}
}

func TestSourceTokenPreflight(t *testing.T) {
	rt := &Runtime{maxSourceBytes: DefaultMaxSourceBytes}
	result, err := rt.TokenizePolicies(context.Background(), string([]byte{0xff}))
	var ce *Error
	if !errors.As(err, &ce) || ce.Kind != KindInput || !reflect.DeepEqual(result, SourceTokens{}) {
		t.Fatalf("invalid UTF-8 reached guest: %+v %v", result, err)
	}
	rt.maxSourceBytes = 10
	result, err = rt.TokenizePolicies(context.Background(), strings.Repeat("x", 20))
	if !errors.As(err, &ce) || ce.Kind != KindLimit || !reflect.DeepEqual(result, SourceTokens{}) {
		t.Fatalf("source limit: %+v %v", result, err)
	}
}
