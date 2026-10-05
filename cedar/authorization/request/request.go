package request

import (
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
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
	Principal entityuid.EntityUID
	Action    entityuid.EntityUID
	Resource  entityuid.EntityUID
	// Context defaults to an empty record.
	Context Context
	// Entities augments the authorizer's entities for this call and recomputes ancestry.
	// Conflicting data for the same UID is an error.
	Entities entity.Entities
}

type Response struct {
	Decision Decision
	// Reasons contains the determining policy IDs in sorted order.
	Reasons []string
	// Errors lists the policies whose evaluation failed, sorted by ID.
	// Cedar skips those policies; the decision stands.
	Errors []diagnostic.PolicyMessage
}
