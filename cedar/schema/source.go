package schema

import (
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Schema defers parsing until a native client uses it.
type Schema struct {
	format syntax.Format
	text   string
}

func SchemaFromCedar(text string) Schema {
	return Schema{format: syntax.FormatCedar, text: text}
}

func SchemaFromJSON(text []byte) Schema {
	return Schema{format: syntax.FormatJSON, text: string(text)}
}

func (s Schema) Format() syntax.Format { return s.format }

func (s Schema) Text() string { return s.text }

func (s Schema) Wire() wire.Source {
	return wire.Source{Format: s.format.Wire(), Text: s.text}
}

func OptionalSchema(s *Schema) *wire.Source {
	if s == nil {
		return nil
	}
	w := s.Wire()
	return &w
}
