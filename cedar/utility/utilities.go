package utility

import (
	context "context"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// ParseEntityUID requires Cedar's normalized UID syntax, including its string escapes.
func (rt *Client) ParseEntityUID(ctx context.Context, TextValue string) (entityuid.EntityUID, error) {
	if err := wire.CheckUTF8(TextValue); err != nil {
		return entityuid.EntityUID{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "parse_uid", "text": TextValue})
	if err != nil {
		return entityuid.EntityUID{}, err
	}
	if result.UID == nil || result.UID.Type == nil || *result.UID.Type == "" || result.UID.ID == nil {
		return entityuid.EntityUID{}, diagnostic.FaultError(fmt.Errorf("UID response has no identity"))
	}
	return entityuid.NewEntityUID(*result.UID.Type, *result.UID.ID), nil
}

// ValidateScopeVariables checks principal, action, and resource against a schema independently of context.
func (rt *Client) ValidateScopeVariables(ctx context.Context, schema schema.Schema, principal, action, resource entityuid.EntityUID) error {
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "scope_validate", "principal": principal.Wire(), "action": action.Wire(), "resource": resource.Wire(), "schema": schema.Wire()})
	return execution.UtilityValidationResult(result, err)
}

// ConfusableStrings checks static policies and templates without requiring a schema.
func (rt *Client) ConfusableStrings(ctx context.Context, policies policy.PolicySet) (decoded []diagnostic.PolicyMessage, decodeErr error) {
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "confusables", "policies": policies.Wire()})
	if err != nil {
		return nil, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	return UtilityWarningsResult(result, err, policies)
}

func UtilityWarningsResult(result execution.UtilityOutput, err error, policies policy.PolicySet) ([]diagnostic.PolicyMessage, error) {
	if err != nil {
		return nil, err
	}
	if result.Warnings == nil {
		return nil, diagnostic.FaultError(fmt.Errorf("confusable response has no warnings"))
	}
	for _, warning := range *result.Warnings {
		if err := diagnostic.CheckDiagnostic(warning.Category, warning.Message, warning.Severity, warning.Spans, diagnostic.SeverityWarning, len(policies.Text())); err != nil {
			return nil, diagnostic.FaultError(fmt.Errorf("decode confusable warning: %w", err))
		}
		if policies.Format() == syntax.FormatJSON && len(warning.Spans) != 0 {
			return nil, diagnostic.FaultError(fmt.Errorf("JSON confusable warning has source spans"))
		}
	}
	return *result.Warnings, nil
}

// LanguageVersion returns Cedar's language version, which differs from the SDK version.
func (rt *Client) LanguageVersion(ctx context.Context) (string, error) {
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "language_version"})
	if err != nil {
		return "", err
	}
	if result.Version == nil || *result.Version == "" {
		return "", diagnostic.FaultError(fmt.Errorf("version response has no version"))
	}
	return *result.Version, nil
}
