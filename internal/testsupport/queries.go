package testsupport

import (
	json "encoding/json"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
)

type QueryFixture struct {
	Name, Operation, Policies string
	PrincipalType             string `json:"principal_type"`
	ResourceType              string `json:"resource_type"`
	Principal, Resource       struct {
		Type string
		ID   *string
	}
	Action    entityuid.EntityUID
	Context   *json.RawMessage
	Entities  *json.RawMessage
	Additions *json.RawMessage
	Replay    bool
}

func QueryUID(value struct {
	Type string
	ID   *string
}) entityuid.EntityUID {
	id := ""
	if value.ID != nil {
		id = *value.ID
	}
	return entityuid.NewEntityUID(value.Type, id)
}

func QueryPartialUID(value struct {
	Type string
	ID   *string
}) cedarpartial.PartialEntityUID {
	if value.ID == nil {
		return cedarpartial.UnknownEntityUID(value.Type)
	}
	return cedarpartial.KnownEntityUID(QueryUID(value))
}
