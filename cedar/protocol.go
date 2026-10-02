package cedar

import (
	"encoding/json"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type loadInput struct {
	Schema   *wire.Source `json:"schema"`
	Policies wire.Source  `json:"policies"`
	Entities Entities     `json:"entities,omitzero"`
}

type loadOutput struct {
	Policies *int        `json:"policies"`
	Error    *wire.Error `json:"error"`
}

type authorizeInput struct {
	Principal wire.UID `json:"principal"`
	Action    wire.UID `json:"action"`
	Resource  wire.UID `json:"resource"`
	Context   Context  `json:"context"`
	Entities  Entities `json:"entities,omitzero"`
}

type authorizeOutput struct {
	Decision string          `json:"decision"`
	Reasons  []string        `json:"reasons"`
	Errors   []PolicyMessage `json:"errors"`
	Error    *wire.Error     `json:"error"`
}

func decodeAuthorize(out []byte) (Response, error) {
	var w authorizeOutput
	if err := json.Unmarshal(out, &w); err != nil {
		return Response{}, faultError(fmt.Errorf("decode authorize response: %w", err))
	}
	if w.Error != nil {
		return Response{}, moduleError(w.Error)
	}
	var d Decision
	switch w.Decision {
	case "allow":
		d = Allow
	case "deny":
		d = Deny
	default:
		return Response{}, faultError(fmt.Errorf("authorize response has decision %q", w.Decision))
	}
	return Response{Decision: d, Reasons: w.Reasons, Errors: w.Errors}, nil
}
