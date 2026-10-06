package input

import (
	bytes "bytes"
	json "encoding/json/v2"
	request "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// PartialEntityUID has a known type and an optional ID. Nil means unknown, not empty.
// This API follows Cedar's experimental type-aware partial evaluation (TPE).
type PartialEntityUID struct {
	Type string  `json:"type"`
	ID   *string `json:"id"`
}

func (u PartialEntityUID) MarshalJSON() ([]byte, error) {
	type uid PartialEntityUID
	return json.Marshal(uid(u))
}

func UnknownEntityUID(typ string) PartialEntityUID { return PartialEntityUID{Type: typ} }

func KnownEntityUID(uid entityuid.EntityUID) PartialEntityUID {
	return PartialEntityUID{Type: uid.Type, ID: &uid.ID}
}

// PartialEntity permits each complete field to be unknown. Attrs and Tags are
// unknown when nil; Parents is unknown when nil, and known empty when non-nil empty.
type PartialEntity struct {
	UID     entityuid.EntityUID
	Attrs   *cedarvalue.Record
	Parents []entityuid.EntityUID
	Tags    *cedarvalue.Record
}

func (e PartialEntity) MarshalJSON() ([]byte, error) {
	var parents []wire.UID
	if e.Parents != nil {
		parents = make([]wire.UID, len(e.Parents))
		for i, p := range e.Parents {
			parents[i] = p.Wire()
		}
	}
	return json.Marshal(struct {
		UID     wire.UID           `json:"uid"`
		Attrs   *cedarvalue.Record `json:"attrs"`
		Parents []wire.UID         `json:"parents"`
		Tags    *cedarvalue.Record `json:"tags"`
	}{e.UID.Wire(), e.Attrs, parents, e.Tags}, json.FormatNilSliceAsNull(true))
}

// PartialEntities is experimental. Absent entities have unknown data; omitted or
// null attrs, parents, and tags are unknown, while {} and [] are known empty.
type PartialEntities struct {
	list   []PartialEntity
	raw    []byte
	isJSON bool
}

func NewPartialEntities(entities ...PartialEntity) PartialEntities {
	return PartialEntities{list: entities}
}

// PartialEntitiesFromJSON accepts Cedar TPE's entity array. Each attrs, parents,
// and tags field must be wholly known or unknown; ancestors must have known parents.
func PartialEntitiesFromJSON(data []byte) PartialEntities {
	return PartialEntities{raw: bytes.Clone(data), isJSON: true}
}

func (e PartialEntities) MarshalJSON() ([]byte, error) {
	if e.isJSON {
		if err := wire.CheckUTF8(string(e.raw)); err != nil {
			return nil, err
		}
		return e.raw, nil
	}
	if e.list == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(e.list)
}

// PartialRequest is experimental. A schema, principal/resource types, and action
// are required. Context is wholly unknown when nil; a pointer to Context{} is known empty.
type PartialRequest struct {
	Principal PartialEntityUID
	Action    entityuid.EntityUID
	Resource  PartialEntityUID
	Context   *request.Context
	// Entities augments loaded concrete entities. Duplicate UIDs are errors.
	Entities PartialEntities
}
