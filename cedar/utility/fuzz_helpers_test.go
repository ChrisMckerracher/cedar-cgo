package utility_test

import (
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	strconv "strconv"
	strings "strings"
	testing "testing"
)

// fuzzUtilSchema declares exactly one fitting scope triple: User / Action::"view" / Photo.
const FuzzUtilSchema = `entity User; entity Photo; action "view" appliesTo { principal: User, resource: Photo, context: {} };`

func RequireUtilKind(t *testing.T, err error, want diagnostic.ErrorKind) {
	t.Helper()
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != want {
		t.Fatalf("want %s error, got %v", want, err)
	}
}

// asciiPlain reports printable-ASCII, backslash-free text: backslashes are
// excluded because escape sequences can spell mixed-script values in ASCII source.
func AsciiPlain(TextValue string) bool {
	return !strings.Contains(TextValue, `\`) &&
		strings.IndexFunc(TextValue, func(r rune) bool { return r < 0x20 || r > 0x7e }) == -1
}

// fuzzCanonicalLong accepts exactly the integer literals Cedar's JSON encoding
// round-trips; "-0", exponents, and out-of-range numbers are module errors.
func fuzzCanonicalLong(TextValue string) bool {
	if TextValue == "-0" {
		return false
	}
	body := strings.TrimPrefix(TextValue, "-")
	if body == "0" {
		return true
	}
	if body == "" || body[0] < '1' || body[0] > '9' {
		return false
	}
	for i := 1; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(TextValue, 10, 64)
	return err == nil
}

// fuzzObjectContext parses a JSON object and reports whether every value is a
// plain Cedar scalar: bool, canonical long, or string. Nested values opt out.
func fuzzObjectContext(data []byte) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return nil, false
	}
	for _, raw := range object {
		TextValue := strings.TrimSpace(string(raw))
		switch {
		case TextValue == "true" || TextValue == "false" || strings.HasPrefix(TextValue, `"`):
		case strings.HasPrefix(TextValue, "-") || (TextValue != "" && TextValue[0] >= '0' && TextValue[0] <= '9'):
			if !fuzzCanonicalLong(TextValue) {
				return object, false
			}
		default:
			return object, false
		}
	}
	return object, true
}
