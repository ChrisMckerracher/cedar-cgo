package utility

import (
	"context"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Values returns native evaluated values, including exact integers and extension values.
func (rt *Client) ContextValues(ctx context.Context, c request.Context) (cedarvalue.EvalRecord, error) {
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "context_values", "context": c})
	if err != nil {
		return nil, err
	}
	if result.Values == nil {
		return nil, diagnostic.FaultError(fmt.Errorf("context response has no values"))
	}
	values := make(cedarvalue.EvalRecord, len(result.Values))
	for key, data := range result.Values {
		value, err := cedarvalue.DecodeEvalResult(data)
		if err != nil {
			return nil, diagnostic.FaultError(fmt.Errorf("decode context attribute %q: %w", key, err))
		}
		values[key] = value
	}
	return values, nil
}

// Get distinguishes a missing attribute from context parsing or evaluation failure.
func (rt *Client) ContextGet(ctx context.Context, c request.Context, key string) (cedarvalue.EvalResult, bool, error) {
	if err := wire.CheckUTF8(key); err != nil {
		return nil, false, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "context_get", "context": c, "key": key})
	if err != nil {
		return nil, false, err
	}
	if result.Found == nil {
		return nil, false, diagnostic.FaultError(fmt.Errorf("context response has no lookup result"))
	}
	if !*result.Found {
		if string(result.Value) != "null" {
			return nil, false, diagnostic.FaultError(fmt.Errorf("missing context attribute has a value"))
		}
		return nil, false, nil
	}
	value, err := cedarvalue.DecodeEvalResult(result.Value)
	if err != nil {
		return nil, false, diagnostic.FaultError(fmt.Errorf("decode context attribute: %w", err))
	}
	return value, true, nil
}

// Merge rejects every overlapping top-level key, including keys with equal values.
// It preserves both inputs and performs no recursive merge.
func (rt *Client) ContextMerge(ctx context.Context, c request.Context, other request.Context) (request.Context, error) {
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "context_merge", "context": c, "other": other})
	if err != nil {
		return request.Context{}, err
	}
	if len(result.Context) == 0 || result.Context[0] != '{' {
		return request.Context{}, diagnostic.FaultError(fmt.Errorf("context response has no merged record"))
	}
	return request.ContextFromJSON(result.Context), nil
}

// Validate checks this context against the action's schema without constructing a request.
func (rt *Client) ContextValidate(ctx context.Context, c request.Context, schema schema.Schema, action entityuid.EntityUID) error {
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "context_validate", "context": c, "schema": schema.Wire(), "action": action.Wire()})
	return execution.UtilityValidationResult(result, err)
}
