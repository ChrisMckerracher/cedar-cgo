package cedar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type utilityOutput struct {
	UID *struct {
		Type *string `json:"type"`
		ID   *string `json:"id"`
	} `json:"uid"`
	Text     *string                    `json:"text"`
	Values   map[string]json.RawMessage `json:"values"`
	Found    *bool                      `json:"found"`
	Value    json.RawMessage            `json:"value"`
	Context  json.RawMessage            `json:"context"`
	Valid    *bool                      `json:"valid"`
	Warnings *[]PolicyMessage           `json:"warnings"`
	Version  *string                    `json:"version"`
	Error    *wire.Error                `json:"error"`
}

func (rt *Runtime) utilityCall(ctx context.Context, input map[string]any) (utilityOutput, error) {
	in, err := json.Marshal(input)
	if err != nil {
		return utilityOutput{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return utilityOutput{}, limitError("utility input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_utilities", in)
	if err != nil {
		return utilityOutput{}, err
	}
	if err := wire.CheckUTF8(string(out)); err != nil {
		return utilityOutput{}, faultError(fmt.Errorf("decode utility response: %w", err))
	}
	var result utilityOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return utilityOutput{}, faultError(fmt.Errorf("decode utility response: %w", err))
	}
	if result.Error != nil {
		return utilityOutput{}, moduleError(result.Error)
	}
	return result, nil
}

// ParseEntityUID requires Cedar's normalized UID syntax, including its string escapes.
func (rt *Runtime) ParseEntityUID(ctx context.Context, text string) (EntityUID, error) {
	if err := wire.CheckUTF8(text); err != nil {
		return EntityUID{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "parse_uid", "text": text})
	if err != nil {
		return EntityUID{}, err
	}
	if result.UID == nil || result.UID.Type == nil || *result.UID.Type == "" || result.UID.ID == nil {
		return EntityUID{}, faultError(fmt.Errorf("UID response has no identity"))
	}
	return NewEntityUID(*result.UID.Type, *result.UID.ID), nil
}

// CedarText renders native Cedar syntax. String remains a Go-quoted log representation.
func (u EntityUID) CedarText(ctx context.Context, rt *Runtime) (string, error) {
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "render_uid", "uid": u.wire()})
	if err != nil {
		return "", err
	}
	if result.Text == nil || *result.Text == "" {
		return "", faultError(fmt.Errorf("UID response has no text"))
	}
	return *result.Text, nil
}

// Values returns native evaluated values, including exact integers and extension values.
func (c Context) Values(ctx context.Context, rt *Runtime) (EvalRecord, error) {
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "context_values", "context": c})
	if err != nil {
		return nil, err
	}
	if result.Values == nil {
		return nil, faultError(fmt.Errorf("context response has no values"))
	}
	values := make(EvalRecord, len(result.Values))
	for key, data := range result.Values {
		value, err := decodeEvalResult(data)
		if err != nil {
			return nil, faultError(fmt.Errorf("decode context attribute %q: %w", key, err))
		}
		values[key] = value
	}
	return values, nil
}

// Get distinguishes a missing attribute from context parsing or evaluation failure.
func (c Context) Get(ctx context.Context, rt *Runtime, key string) (EvalResult, bool, error) {
	if err := wire.CheckUTF8(key); err != nil {
		return nil, false, &Error{Kind: KindInput, Message: err.Error()}
	}
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "context_get", "context": c, "key": key})
	if err != nil {
		return nil, false, err
	}
	if result.Found == nil {
		return nil, false, faultError(fmt.Errorf("context response has no lookup result"))
	}
	if !*result.Found {
		if string(result.Value) != "null" {
			return nil, false, faultError(fmt.Errorf("missing context attribute has a value"))
		}
		return nil, false, nil
	}
	value, err := decodeEvalResult(result.Value)
	if err != nil {
		return nil, false, faultError(fmt.Errorf("decode context attribute: %w", err))
	}
	return value, true, nil
}

// Merge rejects every overlapping top-level key, including keys with equal values.
// It preserves both inputs and performs no recursive merge.
func (c Context) Merge(ctx context.Context, rt *Runtime, other Context) (Context, error) {
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "context_merge", "context": c, "other": other})
	if err != nil {
		return Context{}, err
	}
	if len(result.Context) == 0 || result.Context[0] != '{' {
		return Context{}, faultError(fmt.Errorf("context response has no merged record"))
	}
	return ContextFromJSON(result.Context), nil
}

// Validate checks this context against the action's schema without constructing a request.
func (c Context) Validate(ctx context.Context, rt *Runtime, schema Schema, action EntityUID) error {
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "context_validate", "context": c, "schema": schema.wire(), "action": action.wire()})
	return utilityValidationResult(result, err)
}

// ValidateScopeVariables checks principal, action, and resource against a schema independently of context.
func (rt *Runtime) ValidateScopeVariables(ctx context.Context, schema Schema, principal, action, resource EntityUID) error {
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "scope_validate", "principal": principal.wire(), "action": action.wire(), "resource": resource.wire(), "schema": schema.wire()})
	return utilityValidationResult(result, err)
}

func utilityValidationResult(result utilityOutput, err error) error {
	if err != nil {
		return err
	}
	if result.Valid == nil || !*result.Valid {
		return faultError(fmt.Errorf("validation response has no successful result"))
	}
	return nil
}

// ConfusableStrings checks static policies and templates without requiring a schema.
func (rt *Runtime) ConfusableStrings(ctx context.Context, policies PolicySet) ([]PolicyMessage, error) {
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "confusables", "policies": policies.wire()})
	return utilityWarningsResult(result, err, policies)
}

func utilityWarningsResult(result utilityOutput, err error, policies PolicySet) ([]PolicyMessage, error) {
	if err != nil {
		return nil, err
	}
	if result.Warnings == nil {
		return nil, faultError(fmt.Errorf("confusable response has no warnings"))
	}
	for _, warning := range *result.Warnings {
		if err := checkDiagnostic(warning.Category, warning.Message, warning.Severity, warning.Spans, SeverityWarning, len(policies.text)); err != nil {
			return nil, faultError(fmt.Errorf("decode confusable warning: %w", err))
		}
		if policies.format == FormatJSON && len(warning.Spans) != 0 {
			return nil, faultError(fmt.Errorf("JSON confusable warning has source spans"))
		}
	}
	return *result.Warnings, nil
}

// LanguageVersion returns Cedar's language version, which differs from the SDK version.
func (rt *Runtime) LanguageVersion(ctx context.Context) (string, error) {
	result, err := rt.utilityCall(ctx, map[string]any{"operation": "language_version"})
	if err != nil {
		return "", err
	}
	if result.Version == nil || *result.Version == "" {
		return "", faultError(fmt.Errorf("version response has no version"))
	}
	return *result.Version, nil
}
