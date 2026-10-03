package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// SourceSpan uses UTF-8 byte offsets in the original Cedar source.
// JSON policy inputs have no source spans.
type SourceSpan struct {
	Offset uint64 `json:"offset"`
	Length uint64 `json:"length"`
}

func (s *SourceSpan) UnmarshalJSON(data []byte) error {
	var v struct{ Offset, Length *uint64 }
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if v.Offset == nil || v.Length == nil || *v.Offset > math.MaxUint64-*v.Length {
		return fmt.Errorf("invalid diagnostic source span")
	}
	s.Offset, s.Length = *v.Offset, *v.Length
	return nil
}

type DiagnosticSeverity string

const (
	SeverityError   DiagnosticSeverity = "error"
	SeverityWarning DiagnosticSeverity = "warning"
)

// SchemaWarning contains a native warning category and all native source spans.
type SchemaWarning struct {
	Category string             `json:"category"`
	Severity DiagnosticSeverity `json:"severity"`
	Message  string             `json:"message"`
	Spans    []SourceSpan       `json:"spans,omitempty"`
}

func checkDiagnostic(category, message string, severity DiagnosticSeverity, spans []SourceSpan, want DiagnosticSeverity, sourceBytes int) error {
	if category == "" || message == "" || severity != want {
		return fmt.Errorf("invalid diagnostic category or severity")
	}
	for _, span := range spans {
		if span.Offset > uint64(sourceBytes) || span.Length > uint64(sourceBytes)-span.Offset {
			return fmt.Errorf("diagnostic span exceeds source")
		}
	}
	return nil
}

func decodeSchemaWarnings(data []byte, sourceBytes int) ([]SchemaWarning, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return nil, err
	}
	var response struct {
		Warnings *[]SchemaWarning `json:"warnings"`
		Error    *wire.Error      `json:"error"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, moduleError(response.Error)
	}
	if response.Warnings == nil {
		return nil, fmt.Errorf("schema warning response has no warning list")
	}
	for _, warning := range *response.Warnings {
		if err := checkDiagnostic(warning.Category, warning.Message, warning.Severity, warning.Spans, SeverityWarning, sourceBytes); err != nil {
			return nil, err
		}
	}
	return *response.Warnings, nil
}

// SchemaWarnings parses a complete schema and returns its native syntax warnings.
func (rt *Runtime) SchemaWarnings(ctx context.Context, schema Schema) ([]SchemaWarning, error) {
	in, err := json.Marshal(struct {
		Schema wire.Source `json:"schema"`
	}{schema.wire()})
	if err != nil {
		return nil, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return nil, limitError("schema warning input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_schema_warnings", in)
	if err != nil {
		return nil, err
	}
	warnings, err := decodeSchemaWarnings(out, len(schema.text))
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) {
			return nil, err
		}
		return nil, faultError(fmt.Errorf("decode schema warnings: %w", err))
	}
	return warnings, nil
}

func decodeValidation(data []byte, policyBytes, schemaBytes int) (ValidationResult, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return ValidationResult{}, err
	}
	var response validateOutput
	if err := json.Unmarshal(data, &response); err != nil {
		return ValidationResult{}, err
	}
	if response.Error != nil {
		return ValidationResult{}, moduleError(response.Error)
	}
	if response.Passed == nil || response.Errors == nil || response.Warnings == nil || response.SchemaWarnings == nil {
		return ValidationResult{}, fmt.Errorf("validation response has no result lists")
	}
	for _, group := range []struct {
		messages []PolicyMessage
		severity DiagnosticSeverity
	}{{response.Errors, SeverityError}, {response.Warnings, SeverityWarning}} {
		for _, message := range group.messages {
			if err := checkDiagnostic(message.Category, message.Message, message.Severity, message.Spans, group.severity, policyBytes); err != nil {
				return ValidationResult{}, err
			}
		}
	}
	for _, warning := range response.SchemaWarnings {
		if err := checkDiagnostic(warning.Category, warning.Message, warning.Severity, warning.Spans, SeverityWarning, schemaBytes); err != nil {
			return ValidationResult{}, err
		}
	}
	if *response.Passed != (len(response.Errors) == 0) {
		return ValidationResult{}, fmt.Errorf("validation status conflicts with diagnostics")
	}
	return ValidationResult{Passed: *response.Passed, Errors: response.Errors, Warnings: response.Warnings, SchemaWarnings: response.SchemaWarnings}, nil
}
