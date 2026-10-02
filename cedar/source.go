package cedar

import (
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type Format int

const (
	// FormatCedar selects Cedar's human-readable syntax.
	FormatCedar Format = iota
	FormatJSON
)

func (f Format) wire() string {
	if f == FormatJSON {
		return "json"
	}
	return "cedar"
}

func (f Format) String() string { return f.wire() }

// Schema defers parsing until authorizer creation or [Runtime.Validate].
type Schema struct {
	format Format
	text   string
}

func SchemaFromCedar(text string) Schema { return Schema{format: FormatCedar, text: text} }

func SchemaFromJSON(text []byte) Schema { return Schema{format: FormatJSON, text: string(text)} }

func (s Schema) Format() Format { return s.format }

func (s Schema) Text() string { return s.text }

// PolicySet assigns Cedar-syntax policies IDs "policy0", "policy1", and so on, in order.
type PolicySet struct {
	format Format
	text   string
}

func PoliciesFromCedar(text string) PolicySet { return PolicySet{format: FormatCedar, text: text} }

func PoliciesFromJSON(text []byte) PolicySet {
	return PolicySet{format: FormatJSON, text: string(text)}
}

func (p PolicySet) Format() Format { return p.format }

func (p PolicySet) Text() string { return p.text }

func (s Schema) wire() wire.Source    { return wire.Source{Format: s.format.wire(), Text: s.text} }
func (p PolicySet) wire() wire.Source { return wire.Source{Format: p.format.wire(), Text: p.text} }

func optionalSchema(s *Schema) *wire.Source {
	if s == nil {
		return nil
	}
	w := s.wire()
	return &w
}
