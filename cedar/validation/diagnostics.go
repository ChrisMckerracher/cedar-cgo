package validation

import (
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

func DecodeValidation(data []byte, policyBytes, schemaBytes int) (ValidationResult, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return ValidationResult{}, err
	}
	var response ValidateOutput
	if err := json.Unmarshal(data, &response); err != nil {
		return ValidationResult{}, err
	}
	if response.Error != nil {
		return ValidationResult{}, diagnostic.ModuleError(response.Error)
	}
	if response.Passed == nil || response.Errors == nil || response.Warnings == nil || response.SchemaWarnings == nil {
		return ValidationResult{}, fmt.Errorf("validation response has no result lists")
	}
	for _, group := range []struct {
		messages []diagnostic.PolicyMessage
		severity diagnostic.DiagnosticSeverity
	}{{response.Errors, diagnostic.SeverityError}, {response.Warnings, diagnostic.SeverityWarning}} {
		for _, message := range group.messages {
			if err := diagnostic.CheckDiagnostic(message.Category, message.Message, message.Severity, message.Spans, group.severity, policyBytes); err != nil {
				return ValidationResult{}, err
			}
		}
	}
	for _, warning := range response.SchemaWarnings {
		if err := diagnostic.CheckDiagnostic(warning.Category, warning.Message, warning.Severity, warning.Spans, diagnostic.SeverityWarning, schemaBytes); err != nil {
			return ValidationResult{}, err
		}
	}
	if *response.Passed != (len(response.Errors) == 0) {
		return ValidationResult{}, fmt.Errorf("validation status conflicts with diagnostics")
	}
	return ValidationResult{Passed: *response.Passed, Errors: response.Errors, Warnings: response.Warnings, SchemaWarnings: response.SchemaWarnings}, nil
}
