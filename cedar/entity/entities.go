package entity

import (
	bytes "bytes"
	json "encoding/json/v2"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

type Entity struct {
	UID entityuid.EntityUID
	// Parents needs only direct parents; Cedar computes transitive ancestry.
	Parents []entityuid.EntityUID
	Attrs   cedarvalue.Record
	Tags    cedarvalue.Record
}

type entityJSON struct {
	UID     wire.UID          `json:"uid"`
	Attrs   cedarvalue.Record `json:"attrs"`
	Parents []wire.UID        `json:"parents"`
	Tags    cedarvalue.Record `json:"tags,omitempty"`
}

func (e Entity) MarshalJSON() ([]byte, error) {
	parents := make([]wire.UID, len(e.Parents))
	for i, p := range e.Parents {
		parents[i] = p.Wire()
	}
	return json.Marshal(entityJSON{UID: e.UID.Wire(), Attrs: e.Attrs, Parents: parents, Tags: e.Tags})
}

// Entities defaults to an empty collection.
type Entities struct {
	list   []Entity
	raw    []byte
	isJSON bool
}

func NewEntities(entities ...Entity) Entities { return Entities{list: entities} }

// EntitiesFromJSON expects a Cedar entity array with uid, attrs, parents and optional tags.
func EntitiesFromJSON(data []byte) Entities {
	return Entities{raw: bytes.Clone(data), isJSON: true}
}

func (e Entities) IsZero() bool { return !e.isJSON && e.list == nil }

func (e Entities) MarshalJSON() ([]byte, error) {
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
