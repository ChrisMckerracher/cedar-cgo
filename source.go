package cedar

import (
	"bytes"
	"encoding/json"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Format is the syntax of a [Schema] or a [PolicySet].
type Format int

const (
	// FormatCedar is Cedar's human-readable syntax.
	FormatCedar Format = iota
	// FormatJSON is Cedar's JSON syntax.
	FormatJSON
)

func (f Format) wire() string {
	if f == FormatJSON {
		return "json"
	}
	return "cedar"
}

// String returns "cedar" or "json".
func (f Format) String() string { return f.wire() }

// Schema holds a Cedar schema as source text. Cedar parses it when an
// [Authorizer] loads it, or when [Runtime.Validate] runs.
type Schema struct {
	format Format
	text   string
}

// SchemaFromCedar returns a schema written in Cedar's schema syntax.
func SchemaFromCedar(text string) Schema { return Schema{format: FormatCedar, text: text} }

// SchemaFromJSON returns a schema written in Cedar's JSON schema syntax.
func SchemaFromJSON(text []byte) Schema { return Schema{format: FormatJSON, text: string(text)} }

// Format returns the syntax of the schema text.
func (s Schema) Format() Format { return s.format }

// Text returns the schema text.
func (s Schema) Text() string { return s.text }

// PolicySet holds Cedar policies as source text. Cedar names policies in
// Cedar syntax "policy0", "policy1" and so on, in order.
type PolicySet struct {
	format Format
	text   string
}

// PoliciesFromCedar returns policies written in Cedar's policy syntax.
func PoliciesFromCedar(text string) PolicySet { return PolicySet{format: FormatCedar, text: text} }

// PoliciesFromJSON returns policies written in Cedar's JSON policy syntax.
func PoliciesFromJSON(text []byte) PolicySet {
	return PolicySet{format: FormatJSON, text: string(text)}
}

// Format returns the syntax of the policy text.
func (p PolicySet) Format() Format { return p.format }

// Text returns the policy text.
func (p PolicySet) Text() string { return p.text }

func (s Schema) wire() wire.Source    { return wire.Source{Format: s.format.wire(), Text: s.text} }
func (p PolicySet) wire() wire.Source { return wire.Source{Format: p.format.wire(), Text: p.text} }

// optionalSchema returns the wire form of s, or nil.
func optionalSchema(s *Schema) *wire.Source {
	if s == nil {
		return nil
	}
	w := s.wire()
	return &w
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

// Context holds the context record of a request, either as a Go [Record] or
// as Cedar JSON. The zero value is the empty record.
type Context struct {
	record Record
	raw    []byte
	isJSON bool
}

// NewContext returns a context built from a record.
func NewContext(r Record) Context { return Context{record: r} }

// ContextFromJSON returns a context in Cedar's JSON value format. It must be
// a JSON object.
func ContextFromJSON(data []byte) Context { return Context{raw: bytes.Clone(data), isJSON: true} }

// MarshalJSON implements [json.Marshaler] with Cedar's JSON value format.
func (c Context) MarshalJSON() ([]byte, error) {
	if c.isJSON {
		return c.raw, nil
	}
	return c.record.MarshalJSON()
}
