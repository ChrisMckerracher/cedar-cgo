package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// TokenSpan contains UTF-8 byte offsets. Start is inclusive; End is exclusive.
type TokenSpan struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

func (s *TokenSpan) UnmarshalJSON(data []byte) error {
	var value struct {
		Start *uint32 `json:"start"`
		End   *uint32 `json:"end"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value.Start == nil || value.End == nil {
		return fmt.Errorf("token span requires start and end")
	}
	s.Start, s.End = *value.Start, *value.End
	return nil
}

// SourceToken retains exact token text and native formatter comment summaries.
type SourceToken struct {
	Kind            string    `json:"kind"`
	Text            string    `json:"text"`
	Span            TokenSpan `json:"span"`
	LeadingComments []string  `json:"leading_comments"`
	TrailingComment string    `json:"trailing_comment"`
}

func (t *SourceToken) UnmarshalJSON(data []byte) error {
	var value struct {
		Kind            string               `json:"kind"`
		Text            string               `json:"text"`
		Span            TokenSpan            `json:"span"`
		LeadingComments *sourceTokenComments `json:"leading_comments"`
		TrailingComment *string              `json:"trailing_comment"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value.LeadingComments == nil || value.TrailingComment == nil {
		return fmt.Errorf("source token requires leading and trailing comments")
	}
	*t = SourceToken{value.Kind, value.Text, value.Span, []string(*value.LeadingComments), *value.TrailingComment}
	return nil
}

type sourceTokenComments []string

func (c *sourceTokenComments) UnmarshalJSON(data []byte) error {
	var values []*string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if values == nil {
		return fmt.Errorf("source comments require an array")
	}
	comments := make([]string, len(values))
	for i, value := range values {
		if value == nil {
			return fmt.Errorf("source comments require string entries")
		}
		comments[i] = *value
	}
	*c = comments
	return nil
}

// SourceTokens reports tokens and final comments. The original source retains exact gaps and spacing.
type SourceTokens struct {
	Tokens           []SourceToken `json:"tokens"`
	TrailingComments []string      `json:"trailing_comments"`
}

type sourceTokensOutput struct {
	Tokens           []SourceToken        `json:"tokens"`
	TrailingComments *sourceTokenComments `json:"trailing_comments"`
	Error            *wire.Error          `json:"error"`
}

// TokenizePolicies uses Cedar's formatter lexer without performing semantic policy validation.
// Token spans apply only to the supplied source; lex again after changing it.
func (rt *Runtime) TokenizePolicies(ctx context.Context, text string) (SourceTokens, error) {
	if err := wire.CheckUTF8(text); err != nil {
		return SourceTokens{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	in, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	if err != nil {
		return SourceTokens{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return SourceTokens{}, limitError("token source input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_source_tokens", in)
	if err != nil {
		return SourceTokens{}, err
	}
	return decodeSourceTokens(out, text)
}

func decodeSourceTokens(out []byte, source string) (SourceTokens, error) {
	if err := wire.CheckUTF8(string(out)); err != nil {
		return SourceTokens{}, faultError(fmt.Errorf("decode source tokens: %w", err))
	}
	var result sourceTokensOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return SourceTokens{}, faultError(fmt.Errorf("decode source tokens: %w", err))
	}
	if result.Error != nil {
		return SourceTokens{}, moduleError(result.Error)
	}
	if result.Tokens == nil || result.TrailingComments == nil {
		return SourceTokens{}, faultError(fmt.Errorf("source token response has no token stream"))
	}
	var previous uint32
	for i, token := range result.Tokens {
		span := token.Span
		if !sourceTokenKind(token.Kind) || span.Start < previous || span.Start >= span.End || uint64(span.End) > uint64(len(source)) {
			return SourceTokens{}, faultError(fmt.Errorf("source token response has an invalid kind or span"))
		}
		if !utf8.ValidString(source[span.Start:span.End]) || source[span.Start:span.End] != token.Text {
			return SourceTokens{}, faultError(fmt.Errorf("source token span does not match the source"))
		}
		if !sourceTokenSpelling(token, source) {
			return SourceTokens{}, faultError(fmt.Errorf("source token spelling does not match its kind"))
		}
		gap := source[previous:span.Start]
		if !sourceTokenTrivia(gap, false) {
			return SourceTokens{}, faultError(fmt.Errorf("source token response skips nontrivia source"))
		}
		leading := gap
		if i > 0 {
			trailing, nextLeading := sourceTokenCommentGap(gap)
			if result.Tokens[i-1].TrailingComment != trailing {
				return SourceTokens{}, faultError(fmt.Errorf("source token trailing comment does not match the source"))
			}
			leading = nextLeading
		}
		if !slices.Equal(token.LeadingComments, sourceTokenCommentSummaries(leading)) {
			return SourceTokens{}, faultError(fmt.Errorf("source token leading comments do not match the source"))
		}
		previous = span.End
	}
	gap := source[previous:]
	if !sourceTokenTrivia(gap, true) {
		return SourceTokens{}, faultError(fmt.Errorf("source token response skips nontrivia source"))
	}
	finalComments := gap
	if len(result.Tokens) > 0 {
		trailing, final := sourceTokenCommentGap(gap)
		if result.Tokens[len(result.Tokens)-1].TrailingComment != trailing {
			return SourceTokens{}, faultError(fmt.Errorf("source token trailing comment does not match the source"))
		}
		finalComments = final
	}
	if !slices.Equal([]string(*result.TrailingComments), sourceTokenCommentSummaries(finalComments)) {
		return SourceTokens{}, faultError(fmt.Errorf("source token final comments do not match the source"))
	}
	return SourceTokens{Tokens: result.Tokens, TrailingComments: []string(*result.TrailingComments)}, nil
}

func sourceTokenSpelling(token SourceToken, source string) bool {
	text := token.Text
	after := source[token.Span.End:]
	switch token.Kind {
	case "identifier":
		if len(text) == 0 || !sourceTokenIdentifierByte(text[0], false) || sourceTokenKeyword(text) {
			return false
		}
		for i := 1; i < len(text); i++ {
			if !sourceTokenIdentifierByte(text[i], true) {
				return false
			}
		}
		return len(after) == 0 || !sourceTokenIdentifierByte(after[0], true)
	case "number":
		for i := range len(text) {
			if text[i] < '0' || text[i] > '9' {
				return false
			}
		}
		return len(text) > 0 && (len(after) == 0 || after[0] < '0' || after[0] > '9')
	case "string":
		// The formatter regex permits raw line breaks and does not validate Cedar escape semantics.
		if len(text) < 2 || text[0] != '"' || text[len(text)-1] != '"' {
			return false
		}
		for i := 1; i < len(text)-1; {
			r, size := utf8.DecodeRuneInString(text[i : len(text)-1])
			i += size
			if r == '"' {
				return false
			}
			if r == '\\' {
				if i == len(text)-1 {
					return false
				}
				r, size = utf8.DecodeRuneInString(text[i : len(text)-1])
				if r == '\n' {
					return false
				}
				i += size
			}
		}
		return true
	}
	if text != token.Kind {
		return false
	}
	if sourceTokenKeyword(text) && len(after) > 0 && sourceTokenIdentifierByte(after[0], true) {
		return false
	}
	if len(after) > 0 {
		switch text {
		case ":":
			return after[0] != ':'
		case "!", "<", ">":
			return after[0] != '='
		case "/":
			return after[0] != '/'
		}
	}
	return true
}

func sourceTokenIdentifierByte(b byte, allowDigit bool) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || allowDigit && b >= '0' && b <= '9'
}

func sourceTokenKeyword(text string) bool {
	switch text {
	case "true", "false", "if", "permit", "forbid", "when", "unless", "in", "has", "like", "is", "then", "else", "principal", "action", "resource", "context":
		return true
	}
	return false
}

// The native lexer skips Unicode White_Space and // comments ending at CR, LF, or EOF.
func sourceTokenTrivia(text string, allowEOFComment bool) bool {
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if unicode.IsSpace(r) {
			text = text[size:]
			continue
		}
		if !strings.HasPrefix(text, "//") {
			return false
		}
		end := strings.IndexAny(text, "\r\n")
		if end < 0 {
			return allowEOFComment
		}
		text = text[end:]
	}
	return true
}

// Native comment attachment splits gaps at LF only, then trims their whitespace.
func sourceTokenCommentGap(gap string) (string, string) {
	trailing, leading, _ := strings.Cut(gap, "\n")
	return strings.TrimSpace(trailing), leading
}

func sourceTokenCommentSummaries(text string) []string {
	comments := make([]string, 0)
	for {
		start := strings.Index(text, "//")
		if start < 0 {
			return comments
		}
		text = text[start:]
		end := strings.IndexAny(text, "\r\n")
		if end < 0 {
			return append(comments, strings.TrimSpace(text))
		}
		comments = append(comments, strings.TrimSpace(text[:end]))
		text = text[end:]
	}
}

func sourceTokenKind(kind string) bool {
	if sourceTokenKeyword(kind) {
		return true
	}
	switch kind {
	case "identifier", "number", "string", "?principal", "?resource", "@", ".", ",", ";", ":", "::", "(", ")", "{", "}", "[", "]", "==", "!=", "<", "<=", ">", ">=", "||", "&&", "+", "-", "*", "/", "%", "!":
		return true
	}
	return false
}
