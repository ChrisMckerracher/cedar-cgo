package validation

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"

	errors "errors"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type ValidationResult struct {
	// Passed can be true with warnings; only errors fail validation.
	Passed         bool
	Errors         []diagnostic.PolicyMessage
	Warnings       []diagnostic.PolicyMessage
	SchemaWarnings []diagnostic.SchemaWarning `json:"schema_warnings"`
}

type ValidateInput struct {
	Schema              wire.Source `json:"schema"`
	Policies            wire.Source `json:"policies"`
	MaxDereferenceLevel *uint32     `json:"max_dereference_level,omitempty"`
}

type ValidateOutput struct {
	Passed         *bool                      `json:"passed"`
	Errors         []diagnostic.PolicyMessage `json:"errors"`
	Warnings       []diagnostic.PolicyMessage `json:"warnings"`
	SchemaWarnings []diagnostic.SchemaWarning `json:"schema_warnings"`
	Error          *wire.Error                `json:"error"`
}

// Validate checks policies against a schema with Cedar's strict validator.
// It returns an [*Error] if the schema or the policies do not parse.
func (rt *Client) Validate(ctx context.Context, schema schema.Schema, policies policy.PolicySet) (ValidationResult, error) {
	return rt.validate(ctx, schema, policies, nil)
}

// ValidateWithLevel runs strict validation, then limits entity dereference depth.
// Zero permits no entity dereferences. This uses Cedar's stable level validation API.
func (rt *Client) ValidateWithLevel(ctx context.Context, schema schema.Schema, policies policy.PolicySet, maxDereferenceLevel uint32) (ValidationResult, error) {
	return rt.validate(ctx, schema, policies, &maxDereferenceLevel)
}

func (rt *Client) validate(ctx context.Context, schema schema.Schema, policies policy.PolicySet, level *uint32) (ValidationResult, error) {
	in, err := execution.Encode(ValidateInput{Schema: schema.Wire(), Policies: policies.Wire(), MaxDereferenceLevel: level}, "validation input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return ValidationResult{}, err
	}
	out, err := rt.runtime.CallOnce(ctx, "cgw_validate", in)
	if err != nil {
		return ValidationResult{}, err
	}
	result, err := DecodeValidation(out, len(policies.Text()), len(schema.Text()))
	if err != nil {
		var ce *diagnostic.Error
		if errors.As(err, &ce) {
			return ValidationResult{}, err
		}
		return ValidationResult{}, diagnostic.FaultError(fmt.Errorf("decode validation response: %w", err))
	}
	return result, nil
}
