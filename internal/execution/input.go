package execution

import (
	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
)

// Encode checks the complete JSON envelope against its domain's byte limit.
func Encode(input any, what string, max int) ([]byte, error) {
	// Preserve raw escapes to retain byte limits without repeated unquoting.
	in, err := json.Marshal(input,
		json.Deterministic(true),
		json.FormatNilSliceAsNull(true),
		json.FormatNilMapAsNull(true),
		jsontext.EscapeForHTML(true),
		jsontext.EscapeForJS(true),
		jsontext.PreserveRawStrings(true),
	)
	if err != nil {
		return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	if len(in) > max {
		return nil, diagnostic.LimitError(what, len(in), max)
	}
	return in, nil
}
