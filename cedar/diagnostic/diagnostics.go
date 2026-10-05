package diagnostic

import (
	json "encoding/json"
	fmt "fmt"
	math "math"
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

func CheckDiagnostic(category, message string, severity DiagnosticSeverity, spans []SourceSpan, want DiagnosticSeverity, sourceBytes int) error {
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
