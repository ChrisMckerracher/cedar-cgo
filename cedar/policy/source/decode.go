package source

import (
	json "encoding/json/v2"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	utf8 "unicode/utf8"
)

func DecodeSourceTokens(out []byte, source string) (SourceTokens, error) {
	var result SourceTokensOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("decode source tokens: %w", err))
	}
	if result.Error != nil {
		return SourceTokens{}, diagnostic.ModuleError(result.Error)
	}
	if result.Tokens == nil || result.TrailingComments == nil {
		return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token response has no token stream"))
	}
	var previous uint32
	for _, token := range result.Tokens {
		span := token.Span
		if token.Kind == "" || span.Start < previous || span.Start >= span.End || uint64(span.End) > uint64(len(source)) {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token response has an invalid kind or span"))
		}
		if !utf8.ValidString(source[span.Start:span.End]) || source[span.Start:span.End] != token.Text {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token span does not match the source"))
		}
		previous = span.End
	}
	return SourceTokens{Tokens: result.Tokens, TrailingComments: []string(*result.TrailingComments)}, nil
}
