package source_test

import (
	policysource "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/source"
	strings "strings"
)

func ReconstructTokenSource(source string, tokens policysource.SourceTokens) string {
	var result strings.Builder
	var previous uint32
	for _, token := range tokens.Tokens {
		result.WriteString(source[previous:token.Span.Start])
		result.WriteString(token.Text)
		previous = token.Span.End
	}
	result.WriteString(source[previous:])
	return result.String()
}
