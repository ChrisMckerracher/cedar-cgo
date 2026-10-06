package uid

import (
	json "encoding/json/v2"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
	strconv "strconv"
)

type EntityUID struct {
	Type string
	ID   string
}

func NewEntityUID(typ, id string) EntityUID { return EntityUID{Type: typ, ID: id} }

// String uses Go quoting for logs; some escapes differ from Cedar syntax.
func (u EntityUID) String() string { return u.Type + "::" + strconv.Quote(u.ID) }

func (u EntityUID) Wire() wire.UID { return wire.UID{Type: u.Type, ID: u.ID} }

// Metadata uses flat UID objects and preserves nil lists.
func MetadataUIDs(entities []EntityUID) []wire.UID {
	if entities == nil {
		return nil
	}
	result := make([]wire.UID, len(entities))
	for i, entity := range entities {
		result[i] = entity.Wire()
	}
	return result
}

// MarshalJSON uses Cedar's explicit __entity form to distinguish UIDs from records.
func (u EntityUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Entity wire.UID `json:"__entity"`
	}{u.Wire()})
}
