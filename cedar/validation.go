package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func (rt *Runtime) callOnce(ctx context.Context, op string, input []byte) ([]byte, error) {
	inst, err := rt.module.Instantiate(ctx)
	if err != nil {
		return nil, faultError(err)
	}
	defer inst.Close(context.WithoutCancel(ctx))
	out, err := inst.Call(ctx, op, input, rt.maxResponse)
	if err != nil {
		return nil, faultError(err)
	}
	return out, nil
}

type ValidationResult struct {
	// Passed can be true with warnings; only errors fail validation.
	Passed         bool
	Errors         []PolicyMessage
	Warnings       []PolicyMessage
	SchemaWarnings []SchemaWarning `json:"schema_warnings"`
}

type validateInput struct {
	Schema              wire.Source `json:"schema"`
	Policies            wire.Source `json:"policies"`
	MaxDereferenceLevel *uint32     `json:"max_dereference_level,omitempty"`
}

type validateOutput struct {
	Passed         *bool           `json:"passed"`
	Errors         []PolicyMessage `json:"errors"`
	Warnings       []PolicyMessage `json:"warnings"`
	SchemaWarnings []SchemaWarning `json:"schema_warnings"`
	Error          *wire.Error     `json:"error"`
}

// Validate checks policies against a schema with Cedar's strict validator.
// It returns an [*Error] if the schema or the policies do not parse.
func (rt *Runtime) Validate(ctx context.Context, schema Schema, policies PolicySet) (ValidationResult, error) {
	return rt.validate(ctx, schema, policies, nil)
}

// ValidateWithLevel runs strict validation, then limits entity dereference depth.
// Zero permits no entity dereferences. This uses Cedar's stable level validation API.
func (rt *Runtime) ValidateWithLevel(ctx context.Context, schema Schema, policies PolicySet, maxDereferenceLevel uint32) (ValidationResult, error) {
	return rt.validate(ctx, schema, policies, &maxDereferenceLevel)
}

func (rt *Runtime) validate(ctx context.Context, schema Schema, policies PolicySet, level *uint32) (ValidationResult, error) {
	in, err := json.Marshal(validateInput{Schema: schema.wire(), Policies: policies.wire(), MaxDereferenceLevel: level})
	if err != nil {
		return ValidationResult{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return ValidationResult{}, limitError("validation input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_validate", in)
	if err != nil {
		return ValidationResult{}, err
	}
	result, err := decodeValidation(out, len(policies.text), len(schema.text))
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) {
			return ValidationResult{}, err
		}
		return ValidationResult{}, faultError(fmt.Errorf("decode validation response: %w", err))
	}
	return result, nil
}
