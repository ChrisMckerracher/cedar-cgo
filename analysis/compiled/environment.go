package compiled

import (
	"encoding/json/v2"

	uids "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// RequestEnvironment identifies one schema-defined principal/action/resource combination.
type RequestEnvironment struct {
	PrincipalType string         `json:"principal_type"`
	Action        uids.EntityUID `json:"action"`
	ResourceType  string         `json:"resource_type"`
}

// MarshalJSON preserves flat action UIDs. JSON v2 rejects invalid UTF-8.
func (env RequestEnvironment) MarshalJSON() ([]byte, error) {
	return json.Marshal(compiledEnvironment{
		PrincipalType: env.PrincipalType,
		Action:        wire.UID{Type: env.Action.Type, ID: env.Action.ID},
		ResourceType:  env.ResourceType,
	})
}

func (env *RequestEnvironment) UnmarshalJSON(data []byte) error {
	var decoded compiledEnvironment
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*env = RequestEnvironment{decoded.PrincipalType, uids.NewEntityUID(decoded.Action.Type, decoded.Action.ID), decoded.ResourceType}
	return nil
}
