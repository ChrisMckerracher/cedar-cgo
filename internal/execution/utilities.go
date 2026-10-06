package execution

import (
	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type UtilityOutput struct {
	UID *struct {
		Type *string `json:"type"`
		ID   *string `json:"id"`
	} `json:"uid"`
	Text     *string                     `json:"text"`
	Values   map[string]json.RawMessage  `json:"values"`
	Found    *bool                       `json:"found"`
	Value    json.RawMessage             `json:"value"`
	Context  json.RawMessage             `json:"context"`
	Valid    *bool                       `json:"valid"`
	Warnings *[]diagnostic.PolicyMessage `json:"warnings"`
	Version  *string                     `json:"version"`
	wire.Response
}

func UtilityCall(ctx context.Context, rt Caller, input map[string]any) (UtilityOutput, error) {
	return Exchange[UtilityOutput](ctx, rt, "cgw_utilities", "utility", input)
}

func UtilityValidationResult(result UtilityOutput, err error) error {
	if err != nil {
		return err
	}
	if result.Valid == nil || !*result.Valid {
		return diagnostic.FaultError(fmt.Errorf("validation response has no successful result"))
	}
	return nil
}
