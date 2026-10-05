package source

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	reflect "reflect"
	strings "strings"
	testing "testing"
)

func TestSourceTokenNativeSpellingAndTrivia(t *testing.T) {
	rt, err := newRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(context.Background())
	word := SourceTokenForTest("identifier", "x", 0)
	word.TrailingComment = "// first\r// second"
	for _, tc := range []struct {
		name, source string
		tokens       []SourceToken
		comments     []string
	}{
		{name: "empty"},
		{name: "unicode whitespace", source: "\t\r\n\v\f \u0085\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000"},
		{name: "comment only", source: " // one\r// two\u2028part  \n", comments: []string{"// one", "// two\u2028part"}},
		{name: "keyword", source: "permit", tokens: []SourceToken{SourceTokenForTest("permit", "permit", 0)}},
		{name: "generic kind name is an identifier", source: "number", tokens: []SourceToken{SourceTokenForTest("identifier", "number", 0)}},
		{name: "large lexical number", source: "123456789012345678901234567890", tokens: []SourceToken{SourceTokenForTest("number", "123456789012345678901234567890", 0)}},
		{name: "adjacent number and identifier", source: "123abc", tokens: []SourceToken{SourceTokenForTest("number", "123", 0), SourceTokenForTest("identifier", "abc", 3)}},
		{name: "adjacent slot and identifier", source: "?principality", tokens: []SourceToken{SourceTokenForTest("?principal", "?principal", 0), SourceTokenForTest("identifier", "ity", 10)}},
		{name: "adjacent operator tokens", source: "!<=>>=::::/+-**", tokens: []SourceToken{
			SourceTokenForTest("!", "!", 0), SourceTokenForTest("<=", "<=", 1), SourceTokenForTest(">", ">", 3),
			SourceTokenForTest(">=", ">=", 4), SourceTokenForTest("::", "::", 6), SourceTokenForTest("::", "::", 8),
			SourceTokenForTest("/", "/", 10), SourceTokenForTest("+", "+", 11), SourceTokenForTest("-", "-", 12),
			SourceTokenForTest("*", "*", 13), SourceTokenForTest("*", "*", 14),
		}},
		{name: "adjacent string tokens", source: `"a""b"`, tokens: []SourceToken{SourceTokenForTest("string", `"a"`, 0), SourceTokenForTest("string", `"b"`, 3)}},
		{name: "raw line break in string", source: "\"a\nb\"", tokens: []SourceToken{SourceTokenForTest("string", "\"a\nb\"", 0)}},
		{name: "unsupported semantic escape", source: `"a\q"`, tokens: []SourceToken{SourceTokenForTest("string", `"a\q"`, 0)}},
		{name: "escaped carriage return", source: "\"a\\\rb\"", tokens: []SourceToken{SourceTokenForTest("string", "\"a\\\rb\"", 0)}},
		{name: "lone carriage return gap", source: "x// first\r// second\ry", tokens: []SourceToken{word, SourceTokenForTest("identifier", "y", uint32(len("x// first\r// second\r")))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := DecodeSourceTokens(SourceTokenResponseForTest(t, tc.tokens, tc.comments), tc.source)
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
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != diagnostic.KindPolicies || !reflect.DeepEqual(got, SourceTokens{}) {
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
		{name: "wrong trailing summary", source: "x// trailing", message: "trailing comment", token: SourceTokenForTest("identifier", "x", 0)},
		{name: "wrong final summary", source: "x\n// final", message: "final comments", token: SourceTokenForTest("identifier", "x", 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeSourceTokens(SourceTokenResponseForTest(t, []SourceToken{tc.token}, tc.comments), tc.source)
			var ce *diagnostic.Error
			if !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault || !strings.Contains(ce.Message, tc.message) || !reflect.DeepEqual(got, SourceTokens{}) {
				t.Fatalf("wrong comment attachment result: %+v %v", got, err)
			}
		})
	}
}

func TestSourceTokenPreflight(t *testing.T) {
	rt := &Client{runtime: &execution.Runtime{MaxSourceBytes: execution.DefaultMaxSourceBytes}}
	result, err := rt.TokenizePolicies(context.Background(), string([]byte{0xff}))
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput || !reflect.DeepEqual(result, SourceTokens{}) {
		t.Fatalf("invalid UTF-8 reached native execution: %+v %v", result, err)
	}
	rt.runtime.MaxSourceBytes = 10
	result, err = rt.TokenizePolicies(context.Background(), strings.Repeat("x", 20))
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit || !reflect.DeepEqual(result, SourceTokens{}) {
		t.Fatalf("source limit: %+v %v", result, err)
	}
}
