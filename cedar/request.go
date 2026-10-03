package cedar

import (
	"encoding/json"
	"fmt"
)

// Decision defaults to Deny so uninitialized responses fail closed.
type Decision int

const (
	Deny Decision = iota
	Allow
)

func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "deny"
}

type Request struct {
	Principal EntityUID
	Action    EntityUID
	Resource  EntityUID
	// Context defaults to an empty record.
	Context Context
	// Entities augments the authorizer's entities for this call and recomputes ancestry.
	// Conflicting data for the same UID is an error.
	Entities Entities
}

type Response struct {
	Decision Decision
	// Reasons contains the determining policy IDs in sorted order.
	Reasons []string
	// Errors lists the policies whose evaluation failed, sorted by ID.
	// Cedar skips those policies; the decision stands.
	Errors []PolicyMessage
}

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
