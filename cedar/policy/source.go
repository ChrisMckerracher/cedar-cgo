package policy

import (
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// PolicySet defers parsing. Cedar-syntax policies receive IDs "policy0", "policy1",
// and so on; JSON preserves explicit IDs. Use [Client.ParsePolicySet] for inspection.
type PolicySet struct {
	format syntax.Format
	text   string
}

func PoliciesFromCedar(text string) PolicySet {
	return PolicySet{format: syntax.FormatCedar, text: text}
}

func PoliciesFromJSON(text []byte) PolicySet {
	return PolicySet{format: syntax.FormatJSON, text: string(text)}
}

func (p PolicySet) Format() syntax.Format { return p.format }

func (p PolicySet) Text() string { return p.text }

func (p PolicySet) Wire() wire.Source {
	return wire.Source{Format: p.format.Wire(), Text: p.text}
}
