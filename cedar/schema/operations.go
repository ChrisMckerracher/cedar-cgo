package schema

import (
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// ActionEntities extracts native action entities with their transitive parent relationships.
func (rt *Client) ActionEntities(ctx context.Context, schema Schema) (decoded entity.Entities, decodeErr error) {
	var result struct {
		Entities json.RawMessage `json:"entities"`
	}
	if err := rt.schemaOperation(ctx, struct {
		Op     string      `json:"op"`
		Schema wire.Source `json:"schema"`
	}{"actions", schema.Wire()}, &result); err != nil {
		return entity.Entities{}, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	var entities []json.RawMessage
	if err := json.Unmarshal(result.Entities, &entities); err != nil || entities == nil {
		return entity.Entities{}, diagnostic.FaultError(fmt.Errorf("schema action response has no entity array"))
	}
	return entity.EntitiesFromJSON(result.Entities), nil
}

func (rt *Client) schemaOperation(ctx context.Context, input any, result any) (decodeErr error) {
	in, err := execution.Encode(input, "schema operation input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return err
	}
	defer func() { decodeErr = execution.CompletionError(ctx, decodeErr) }()
	out, err := rt.runtime.CallOnce(ctx, "cgw_schemas", in)
	if err != nil {
		return err
	}
	var envelope struct {
		Error *wire.Error `json:"error"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		return diagnostic.FaultError(fmt.Errorf("decode schema operation response: %w", err))
	}
	if envelope.Error != nil {
		return diagnostic.ModuleError(envelope.Error)
	}
	if err := json.Unmarshal(out, result); err != nil {
		return diagnostic.FaultError(fmt.Errorf("decode schema operation result: %w", err))
	}
	return nil
}

func JsonObject(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(data, &object) == nil && object != nil
}
