package cedar

import (
	"bytes"
	"encoding/json"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"strconv"
)

// EntityUID identifies an entity by its type and ID, such as
// Type "Photos::User" and ID "alice".
type EntityUID struct {
	Type string
	ID   string
}

// NewEntityUID returns the UID of the entity with type typ and ID id.
func NewEntityUID(typ, id string) EntityUID { return EntityUID{Type: typ, ID: id} }

// String returns the UID for logs, such as Photos::User::"alice". It quotes
// the ID with Go's rules, which differ from Cedar's for some characters.
func (u EntityUID) String() string { return u.Type + "::" + strconv.Quote(u.ID) }

func (u EntityUID) wire() wire.UID { return wire.UID{Type: u.Type, ID: u.ID} }

// MarshalJSON implements [json.Marshaler]. It writes the explicit
// {"__entity": {"type": ..., "id": ...}} form.
func (u EntityUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Entity wire.UID `json:"__entity"`
	}{u.wire()})
}

// Entity is a Cedar entity: a UID, attributes, ancestors and tags.
type Entity struct {
	UID EntityUID
	// Parents lists the direct parents. Cedar computes the transitive
	// closure.
	Parents []EntityUID
	Attrs   Record
	Tags    Record
}

type entityJSON struct {
	UID     wire.UID   `json:"uid"`
	Attrs   Record     `json:"attrs"`
	Parents []wire.UID `json:"parents"`
	Tags    Record     `json:"tags,omitempty"`
}

// MarshalJSON implements [json.Marshaler] with Cedar's entity JSON format.
func (e Entity) MarshalJSON() ([]byte, error) {
	parents := make([]wire.UID, len(e.Parents))
	for i, p := range e.Parents {
		parents[i] = p.wire()
	}
	return json.Marshal(entityJSON{UID: e.UID.wire(), Attrs: e.Attrs, Parents: parents, Tags: e.Tags})
}

// Entities holds Cedar entities, either as Go values or as Cedar's entity
// JSON. The zero value holds no entities.
type Entities struct {
	list   []Entity
	raw    []byte
	isJSON bool
}

// NewEntities returns entities built from Go values.
func NewEntities(entities ...Entity) Entities { return Entities{list: entities} }

// EntitiesFromJSON returns entities in Cedar's entity JSON format: an array
// of objects with "uid", "attrs", "parents" and optional "tags".
func EntitiesFromJSON(data []byte) Entities {
	return Entities{raw: bytes.Clone(data), isJSON: true}
}

// IsZero reports whether e is the zero value.
func (e Entities) IsZero() bool { return !e.isJSON && e.list == nil }

// MarshalJSON implements [json.Marshaler] with Cedar's entity JSON format.
func (e Entities) MarshalJSON() ([]byte, error) {
	if e.isJSON {
		return e.raw, nil
	}
	if e.list == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(e.list)
}
