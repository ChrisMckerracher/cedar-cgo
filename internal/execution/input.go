package execution

import (
	"encoding/json"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
)

// Encode checks the complete JSON envelope against its domain's byte limit.
func Encode(input any, what string, max int) ([]byte, error) {
	in, err := json.Marshal(input)
	if err != nil {
		return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	if len(in) > max {
		return nil, diagnostic.LimitError(what, len(in), max)
	}
	return in, nil
}
