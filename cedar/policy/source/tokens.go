package source

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
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
		LeadingComments *SourceTokenComments `json:"leading_comments"`
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

type SourceTokenComments []string

func (c *SourceTokenComments) UnmarshalJSON(data []byte) error {
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

type SourceTokensOutput struct {
	Tokens           []SourceToken        `json:"tokens"`
	TrailingComments *SourceTokenComments `json:"trailing_comments"`
	Error            *wire.Error          `json:"error"`
}

// TokenizePolicies uses Cedar's formatter lexer without performing semantic policy validation.
// Token spans apply only to the supplied source; lex again after changing it.
func (rt *Client) TokenizePolicies(ctx context.Context, TextValue string) (SourceTokens, error) {
	if err := wire.CheckUTF8(TextValue); err != nil {
		return SourceTokens{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	in, err := execution.Encode(struct {
		Text string `json:"text"`
	}{TextValue}, "token source input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return SourceTokens{}, err
	}
	out, err := rt.runtime.CallOnce(ctx, "cgw_source_tokens", in)
	if err != nil {
		return SourceTokens{}, err
	}
	return DecodeSourceTokens(out, TextValue)
}
