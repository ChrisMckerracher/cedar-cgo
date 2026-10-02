package cedar

// Decision is the outcome of an authorization request. The zero value is
// Deny.
type Decision int

const (
	// Deny means the request is not authorized.
	Deny Decision = iota
	// Allow means the request is authorized.
	Allow
)

// String returns "allow" or "deny".
func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "deny"
}

// Request is one authorization request.
type Request struct {
	Principal EntityUID
	Action    EntityUID
	Resource  EntityUID
	// Context is the request context. The zero value is the empty record.
	Context Context
	// Entities, if not zero, adds entities for this request only. Cedar
	// merges them with the authorizer's entities and recomputes the
	// ancestor closure. An entity that is in both, with different data,
	// is an error.
	Entities Entities
}

// Response is the result of an authorization request.
type Response struct {
	Decision Decision
	// Reasons lists the IDs of the policies that determined the decision,
	// sorted.
	Reasons []string
	// Errors lists the policies whose evaluation failed, sorted by ID.
	// Cedar skips those policies; the decision stands.
	Errors []PolicyMessage
}

// PolicyMessage is a message about one policy.
type PolicyMessage struct {
	PolicyID string `json:"policy_id"`
	Message  string `json:"message"`
}
