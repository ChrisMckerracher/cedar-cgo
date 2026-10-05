package source

import (
	strings "strings"
	unicode "unicode"
	utf8 "unicode/utf8"
)

func SourceTokenSpelling(token SourceToken, source string) bool {
	TextValue := token.Text
	after := source[token.Span.End:]
	switch token.Kind {
	case "identifier":
		if len(TextValue) == 0 || !SourceTokenIdentifierByte(TextValue[0], false) || SourceTokenKeyword(TextValue) {
			return false
		}
		for i := 1; i < len(TextValue); i++ {
			if !SourceTokenIdentifierByte(TextValue[i], true) {
				return false
			}
		}
		return len(after) == 0 || !SourceTokenIdentifierByte(after[0], true)
	case "number":
		for i := range len(TextValue) {
			if TextValue[i] < '0' || TextValue[i] > '9' {
				return false
			}
		}
		return len(TextValue) > 0 && (len(after) == 0 || after[0] < '0' || after[0] > '9')
	case "string":
		// The formatter regex permits raw line breaks and does not validate Cedar escape semantics.
		if len(TextValue) < 2 || TextValue[0] != '"' || TextValue[len(TextValue)-1] != '"' {
			return false
		}
		for i := 1; i < len(TextValue)-1; {
			r, size := utf8.DecodeRuneInString(TextValue[i : len(TextValue)-1])
			i += size
			if r == '"' {
				return false
			}
			if r == '\\' {
				if i == len(TextValue)-1 {
					return false
				}
				r, size = utf8.DecodeRuneInString(TextValue[i : len(TextValue)-1])
				if r == '\n' {
					return false
				}
				i += size
			}
		}
		return true
	}
	if TextValue != token.Kind {
		return false
	}
	if SourceTokenKeyword(TextValue) && len(after) > 0 && SourceTokenIdentifierByte(after[0], true) {
		return false
	}
	if len(after) > 0 {
		switch TextValue {
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

func SourceTokenIdentifierByte(b byte, allowDigit bool) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || allowDigit && b >= '0' && b <= '9'
}

func SourceTokenKeyword(TextValue string) bool {
	switch TextValue {
	case "true", "false", "if", "permit", "forbid", "when", "unless", "in", "has", "like", "is", "then", "else", "principal", "action", "resource", "context":
		return true
	}
	return false
}

// The native lexer skips Unicode White_Space and // comments ending at CR, LF, or EOF.
func SourceTokenTrivia(TextValue string, allowEOFComment bool) bool {
	for len(TextValue) > 0 {
		r, size := utf8.DecodeRuneInString(TextValue)
		if unicode.IsSpace(r) {
			TextValue = TextValue[size:]
			continue
		}
		if !strings.HasPrefix(TextValue, "//") {
			return false
		}
		end := strings.IndexAny(TextValue, "\r\n")
		if end < 0 {
			return allowEOFComment
		}
		TextValue = TextValue[end:]
	}
	return true
}

// Native comment attachment splits gaps at LF only, then trims their whitespace.
func SourceTokenCommentGap(gap string) (string, string) {
	trailing, leading, _ := strings.Cut(gap, "\n")
	return strings.TrimSpace(trailing), leading
}
