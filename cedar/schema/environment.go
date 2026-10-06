package schema

import (
	"encoding/json/v2"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// RequestEnvironment describes a schema principal/action/resource combination.
// It describes potential applicability, without granting authorization.
type RequestEnvironment struct {
	PrincipalType     string        `json:"principal_type"`
	Action            uid.EntityUID `json:"action"`
	ResourceType      string        `json:"resource_type"`
	PrincipalSlotType *string       `json:"principal_slot_type,omitzero"`
	ResourceSlotType  *string       `json:"resource_slot_type,omitzero"`
}

// MarshalJSON preserves the flat UID fields used by native applicability metadata.
func (env RequestEnvironment) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PrincipalType     string   `json:"principal_type"`
		Action            wire.UID `json:"action"`
		ResourceType      string   `json:"resource_type"`
		PrincipalSlotType *string  `json:"principal_slot_type,omitzero"`
		ResourceSlotType  *string  `json:"resource_slot_type,omitzero"`
	}{env.PrincipalType, env.Action.Wire(), env.ResourceType, env.PrincipalSlotType, env.ResourceSlotType})
}
