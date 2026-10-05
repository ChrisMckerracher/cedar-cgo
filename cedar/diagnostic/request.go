package diagnostic

import (
	json "encoding/json"
	fmt "fmt"
)

type PolicyMessage struct {
	PolicyID string             `json:"policy_id"`
	Message  string             `json:"message"`
	Category string             `json:"category,omitempty"`
	Severity DiagnosticSeverity `json:"severity,omitempty"`
	Spans    []SourceSpan       `json:"spans,omitempty"`
}

func (m *PolicyMessage) UnmarshalJSON(data []byte) error {
	type message PolicyMessage
	var value struct {
		*message
		PolicyID *string `json:"policy_id"`
	}
	var parsed message
	value.message = &parsed
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	// An omitted ID must not become the valid empty policy ID.
	if value.PolicyID == nil {
		return fmt.Errorf("policy diagnostic has no policy ID")
	}
	parsed.PolicyID = *value.PolicyID
	*m = PolicyMessage(parsed)
	return nil
}
