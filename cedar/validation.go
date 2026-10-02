package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// callOnce runs one operation on a fresh instance and closes it.
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

// ValidationResult is the outcome of strict validation.
type ValidationResult struct {
	// Passed is true when the validator found no errors. Warnings do not
	// fail validation.
	Passed   bool
	Errors   []PolicyMessage
	Warnings []PolicyMessage
}

type validateInput struct {
	Schema   wire.Source `json:"schema"`
	Policies wire.Source `json:"policies"`
}

type validateOutput struct {
	Passed   *bool           `json:"passed"`
	Errors   []PolicyMessage `json:"errors"`
	Warnings []PolicyMessage `json:"warnings"`
	Error    *wire.Error     `json:"error"`
}

// Validate checks policies against a schema with Cedar's strict validator.
// It returns an [*Error] if the schema or the policies do not parse.
func (rt *Runtime) Validate(ctx context.Context, schema Schema, policies PolicySet) (ValidationResult, error) {
	in, err := json.Marshal(validateInput{Schema: schema.wire(), Policies: policies.wire()})
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
	var resp validateOutput
	if err := json.Unmarshal(out, &resp); err != nil {
		return ValidationResult{}, faultError(fmt.Errorf("decode validation response: %w", err))
	}
	if resp.Error != nil {
		return ValidationResult{}, moduleError(resp.Error)
	}
	if resp.Passed == nil {
		return ValidationResult{}, faultError(fmt.Errorf("validation response has no result"))
	}
	return ValidationResult{Passed: *resp.Passed, Errors: resp.Errors, Warnings: resp.Warnings}, nil
}
