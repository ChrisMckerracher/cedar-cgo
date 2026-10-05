package schema

import (
	"encoding/json"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// RequestEnvironment describes a schema principal/action/resource combination.
// It describes potential applicability, without granting authorization.
type RequestEnvironment struct {
	PrincipalType     string        `json:"principal_type"`
	Action            uid.EntityUID `json:"action"`
	ResourceType      string        `json:"resource_type"`
	PrincipalSlotType *string       `json:"principal_slot_type,omitempty"`
	ResourceSlotType  *string       `json:"resource_slot_type,omitempty"`
}

// MarshalJSON preserves the flat UID fields used by native applicability metadata.
func (env RequestEnvironment) MarshalJSON() ([]byte, error) {
	if err := wire.CheckUTF8(env.PrincipalType, env.ResourceType); err != nil {
		return nil, err
	}
	for _, slot := range []*string{env.PrincipalSlotType, env.ResourceSlotType} {
		if slot != nil {
			if err := wire.CheckUTF8(*slot); err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(struct {
		PrincipalType     string   `json:"principal_type"`
		Action            wire.UID `json:"action"`
		ResourceType      string   `json:"resource_type"`
		PrincipalSlotType *string  `json:"principal_slot_type,omitempty"`
		ResourceSlotType  *string  `json:"resource_slot_type,omitempty"`
	}{env.PrincipalType, env.Action.Wire(), env.ResourceType, env.PrincipalSlotType, env.ResourceSlotType})
}
