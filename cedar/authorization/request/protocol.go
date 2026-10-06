package request

import (
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

type AuthorizeInput struct {
	Principal wire.UID        `json:"principal"`
	Action    wire.UID        `json:"action"`
	Resource  wire.UID        `json:"resource"`
	Context   Context         `json:"context"`
	Entities  entity.Entities `json:"entities,omitzero"`
}

type AuthorizeOutput struct {
	Decision string                     `json:"decision"`
	Reasons  []string                   `json:"reasons"`
	Errors   []diagnostic.PolicyMessage `json:"errors"`
	Error    *wire.Error                `json:"error"`
}

func DecodeAuthorize(out []byte) (Response, error) {
	if err := wire.CheckUTF8(string(out)); err != nil {
		return Response{}, diagnostic.FaultError(err)
	}
	var w AuthorizeOutput
	if err := json.Unmarshal(out, &w); err != nil {
		return Response{}, diagnostic.FaultError(fmt.Errorf("decode authorize response: %w", err))
	}
	if w.Error != nil {
		return Response{}, diagnostic.ModuleError(w.Error)
	}
	if w.Reasons == nil || w.Errors == nil {
		return Response{}, diagnostic.FaultError(fmt.Errorf("authorize response has no result lists"))
	}
	var d Decision
	switch w.Decision {
	case "allow":
		d = Allow
	case "deny":
		d = Deny
	default:
		return Response{}, diagnostic.FaultError(fmt.Errorf("authorize response has decision %q", w.Decision))
	}
	return Response{Decision: d, Reasons: w.Reasons, Errors: w.Errors}, nil
}
