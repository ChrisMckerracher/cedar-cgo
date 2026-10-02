package cedar

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
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

// Value is a Cedar value: [Bool], [Long], [String], [Set], [Record],
// [EntityUID], [Decimal], [IPAddr], [Datetime] or [Duration].
//
// Each value marshals to Cedar's JSON value format. Cedar parses that JSON,
// so its rules apply: for example, a [Record] whose only key is "__entity" or
// "__extn" reads as an entity reference or an extension value.
type Value interface {
	json.Marshaler
	cedarValue()
}

// Bool is a Cedar boolean.
type Bool bool

// Long is a Cedar 64-bit signed integer.
type Long int64

// String is a Cedar string.
type String string

// Set is a Cedar set. Cedar ignores the order and removes duplicates.
type Set []Value

// Record is a Cedar record.
type Record map[string]Value

// Decimal is a Cedar decimal, written as Cedar's decimal() constructor
// accepts it, such as "12.3456".
type Decimal string

// IPAddr is a Cedar IP address or range, written as Cedar's ip()
// constructor accepts it, such as "10.0.0.0/8".
type IPAddr string

// Datetime is a Cedar datetime, written as Cedar's datetime() constructor
// accepts it, such as "2026-10-01T12:00:00Z".
type Datetime string

// Duration is a Cedar duration, written as Cedar's duration() constructor
// accepts it, such as "1h30m".
type Duration string

func (Bool) cedarValue()      {}
func (Long) cedarValue()      {}
func (String) cedarValue()    {}
func (Set) cedarValue()       {}
func (Record) cedarValue()    {}
func (EntityUID) cedarValue() {}
func (Decimal) cedarValue()   {}
func (IPAddr) cedarValue()    {}
func (Datetime) cedarValue()  {}
func (Duration) cedarValue()  {}

// MarshalJSON implements [json.Marshaler].
func (v Bool) MarshalJSON() ([]byte, error) { return json.Marshal(bool(v)) }

// MarshalJSON implements [json.Marshaler].
func (v Long) MarshalJSON() ([]byte, error) { return json.Marshal(int64(v)) }

// MarshalJSON implements [json.Marshaler].
func (v String) MarshalJSON() ([]byte, error) { return json.Marshal(string(v)) }

// MarshalJSON implements [json.Marshaler].
func (v Set) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("[]"), nil
	}
	if err := checkValues(v); err != nil {
		return nil, err
	}
	return json.Marshal([]Value(v))
}

// MarshalJSON implements [json.Marshaler].
func (v Record) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	for k, e := range v {
		if e == nil {
			return nil, fmt.Errorf("cedar: record attribute %q is nil", k)
		}
	}
	return json.Marshal(map[string]Value(v))
}

// MarshalJSON implements [json.Marshaler]. It writes the explicit
// {"__entity": {"type": ..., "id": ...}} form.
func (u EntityUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Entity wire.UID `json:"__entity"`
	}{u.wire()})
}

type extnJSON struct {
	Extn struct {
		Fn  string `json:"fn"`
		Arg string `json:"arg"`
	} `json:"__extn"`
}

func marshalExtn(fn, arg string) ([]byte, error) {
	var e extnJSON
	e.Extn.Fn, e.Extn.Arg = fn, arg
	return json.Marshal(e)
}

// MarshalJSON implements [json.Marshaler].
func (v Decimal) MarshalJSON() ([]byte, error) { return marshalExtn("decimal", string(v)) }

// MarshalJSON implements [json.Marshaler].
func (v IPAddr) MarshalJSON() ([]byte, error) { return marshalExtn("ip", string(v)) }

// MarshalJSON implements [json.Marshaler].
func (v Datetime) MarshalJSON() ([]byte, error) { return marshalExtn("datetime", string(v)) }

// MarshalJSON implements [json.Marshaler].
func (v Duration) MarshalJSON() ([]byte, error) { return marshalExtn("duration", string(v)) }

func checkValues(vs []Value) error {
	for i, e := range vs {
		if e == nil {
			return fmt.Errorf("cedar: set element %d is nil", i)
		}
	}
	return nil
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
