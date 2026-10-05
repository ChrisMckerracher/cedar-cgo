package source

import (
	strings "strings"
)

func SourceTokenCommentSummaries(TextValue string) []string {
	comments := make([]string, 0)
	for {
		start := strings.Index(TextValue, "//")
		if start < 0 {
			return comments
		}
		TextValue = TextValue[start:]
		end := strings.IndexAny(TextValue, "\r\n")
		if end < 0 {
			return append(comments, strings.TrimSpace(TextValue))
		}
		comments = append(comments, strings.TrimSpace(TextValue[:end]))
		TextValue = TextValue[end:]
	}
}

func SourceTokenKind(kind string) bool {
	if SourceTokenKeyword(kind) {
		return true
	}
	switch kind {
	case "identifier", "number", "string", "?principal", "?resource", "@", ".", ",", ";", ":", "::", "(", ")", "{", "}", "[", "]", "==", "!=", "<", "<=", ">", ">=", "||", "&&", "+", "-", "*", "/", "%", "!":
		return true
	}
	return false
}
