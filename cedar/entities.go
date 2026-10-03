package cedar

import (
	"bytes"
	"encoding/json"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"strconv"
)

type EntityUID struct {
	Type string
	ID   string
}

func NewEntityUID(typ, id string) EntityUID { return EntityUID{Type: typ, ID: id} }

// String uses Go quoting for logs; some escapes differ from Cedar syntax.
func (u EntityUID) String() string { return u.Type + "::" + strconv.Quote(u.ID) }

func (u EntityUID) wire() wire.UID { return wire.UID{Type: u.Type, ID: u.ID} }

// Metadata uses flat UID objects and preserves nil lists.
func metadataUIDs(entities []EntityUID) []wire.UID {
	if entities == nil {
		return nil
	}
	result := make([]wire.UID, len(entities))
	for i, entity := range entities {
		result[i] = entity.wire()
	}
	return result
}

// MarshalJSON uses Cedar's explicit __entity form to distinguish UIDs from records.
func (u EntityUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Entity wire.UID `json:"__entity"`
	}{u.wire()})
}

type Entity struct {
	UID EntityUID
	// Parents needs only direct parents; Cedar computes transitive ancestry.
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

func (e Entity) MarshalJSON() ([]byte, error) {
	parents := make([]wire.UID, len(e.Parents))
	for i, p := range e.Parents {
		parents[i] = p.wire()
	}
	return json.Marshal(entityJSON{UID: e.UID.wire(), Attrs: e.Attrs, Parents: parents, Tags: e.Tags})
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
