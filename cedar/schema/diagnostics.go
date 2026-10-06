package schema

import (
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"

	context "context"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

func DecodeSchemaWarnings(data []byte, sourceBytes int) ([]diagnostic.SchemaWarning, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return nil, err
	}
	var response struct {
		Warnings *[]diagnostic.SchemaWarning `json:"warnings"`
		Error    *wire.Error                 `json:"error"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, diagnostic.ModuleError(response.Error)
	}
	if response.Warnings == nil {
		return nil, fmt.Errorf("schema warning response has no warning list")
	}
	for _, warning := range *response.Warnings {
		if err := diagnostic.CheckDiagnostic(warning.Category, warning.Message, warning.Severity, warning.Spans, diagnostic.SeverityWarning, sourceBytes); err != nil {
			return nil, err
		}
	}
	return *response.Warnings, nil
}

// SchemaWarnings parses a complete schema and returns its native syntax warnings.
func (rt *Client) SchemaWarnings(ctx context.Context, schema Schema) (decoded []diagnostic.SchemaWarning, decodeErr error) {
	in, err := execution.Encode(struct {
		Schema wire.Source `json:"schema"`
	}{schema.Wire()}, "schema warning input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return nil, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	out, err := rt.runtime.CallOnce(ctx, "cgw_schema_warnings", in)
	if err != nil {
		return nil, err
	}
	warnings, err := DecodeSchemaWarnings(out, len(schema.text))
	if err != nil {
		if _, ok := errors.AsType[*diagnostic.Error](err); ok {
			return nil, err
		}
		return nil, diagnostic.FaultError(fmt.Errorf("decode schema warnings: %w", err))
	}
	return warnings, nil
}
