package source

import (
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	slices "slices"
	utf8 "unicode/utf8"
)

func DecodeSourceTokens(out []byte, source string) (SourceTokens, error) {
	if err := wire.CheckUTF8(string(out)); err != nil {
		return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("decode source tokens: %w", err))
	}
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
	for i, token := range result.Tokens {
		span := token.Span
		if !SourceTokenKind(token.Kind) || span.Start < previous || span.Start >= span.End || uint64(span.End) > uint64(len(source)) {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token response has an invalid kind or span"))
		}
		if !utf8.ValidString(source[span.Start:span.End]) || source[span.Start:span.End] != token.Text {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token span does not match the source"))
		}
		if !SourceTokenSpelling(token, source) {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token spelling does not match its kind"))
		}
		gap := source[previous:span.Start]
		if !SourceTokenTrivia(gap, false) {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token response skips nontrivia source"))
		}
		leading := gap
		if i > 0 {
			trailing, nextLeading := SourceTokenCommentGap(gap)
			if result.Tokens[i-1].TrailingComment != trailing {
				return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token trailing comment does not match the source"))
			}
			leading = nextLeading
		}
		if !slices.Equal(token.LeadingComments, SourceTokenCommentSummaries(leading)) {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token leading comments do not match the source"))
		}
		previous = span.End
	}
	gap := source[previous:]
	if !SourceTokenTrivia(gap, true) {
		return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token response skips nontrivia source"))
	}
	finalComments := gap
	if len(result.Tokens) > 0 {
		trailing, final := SourceTokenCommentGap(gap)
		if result.Tokens[len(result.Tokens)-1].TrailingComment != trailing {
			return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token trailing comment does not match the source"))
		}
		finalComments = final
	}
	if !slices.Equal([]string(*result.TrailingComments), SourceTokenCommentSummaries(finalComments)) {
		return SourceTokens{}, diagnostic.FaultError(fmt.Errorf("source token final comments do not match the source"))
	}
	return SourceTokens{Tokens: result.Tokens, TrailingComments: []string(*result.TrailingComments)}, nil
}
