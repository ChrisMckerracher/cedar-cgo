package generator

import (
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	rapid "pgregory.net/rapid"
	unicode "unicode"
	utf8 "unicode/utf8"
)

// propGenUnicode draws valid UTF-8 from edge runes and broad script tables.
// U+FFFD must keep its identity without normalization; NUL and quotes stress
// JSON escaping, which still preserves identity bytes.
var PropGenUnicode = rapid.StringOfN(
	rapid.RuneFrom([]rune{0, '\ufffd', '\U0001f600', '雪', 'a', '"', '\\', '\n'}, unicode.L, unicode.M),
	0, 8, 64,
)

// propGenMalformed turns valid text into invalid UTF-8 through four strategies:
// a stray continuation byte, a never-valid byte, a truncated trailing rune, and
// a surrogate sequence. Every strategy yields invalid UTF-8 for any input.
func PropGenMalformed(t *rapid.T, TextValue string) string {
	t.Helper()
	b := []byte(TextValue)
	var out []byte
	switch rapid.IntRange(0, 3).Draw(t, "corruption") {
	case 0:
		at := rapid.IntRange(0, len(b)).Draw(t, "at")
		stray := byte(0x80 + rapid.IntRange(0, 0x3f).Draw(t, "stray"))
		out = append(append(append([]byte{}, b[:at]...), stray), b[at:]...)
	case 1:
		never := byte(0xfe + rapid.IntRange(0, 1).Draw(t, "never"))
		out = append(append([]byte{}, b...), never)
	case 2:
		// Truncate the final byte of a multibyte trailing rune; ASCII endings
		// fall back to the never-valid byte so the result is always malformed.
		if _, size := utf8.DecodeLastRune(b); size > 1 {
			out = b[:len(b)-1]
		} else {
			out = append(append([]byte{}, b...), 0xff)
		}
	default:
		at := rapid.IntRange(0, len(b)).Draw(t, "at")
		out = append(append([]byte{}, b[:at]...), 0xed, 0xa0, 0x80)
		out = append(out, b[at:]...)
	}
	if utf8.Valid(out) {
		t.Fatalf("corruption strategy produced valid UTF-8: %q -> %q", TextValue, out)
	}
	return string(out)
}

func PropRequireUTF8InputError(pt *rapid.T, err error) {
	pt.Helper()
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
		pt.Fatalf("got %v; want KindInput", err)
	}
}
