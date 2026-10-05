package schema

import (
	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// SchemaFragment retains declarations that can reference other fragments.
// Parsing and resolution occur in the native Cedar module.
type SchemaFragment struct {
	format syntax.Format
	text   string
}

func SchemaFragmentFromCedar(text string) SchemaFragment {
	return SchemaFragment{format: syntax.FormatCedar, text: text}
}

func SchemaFragmentFromJSON(text []byte) SchemaFragment {
	return SchemaFragment{format: syntax.FormatJSON, text: string(text)}
}

func (f SchemaFragment) Format() syntax.Format { return f.format }

func (f SchemaFragment) Text() string { return f.text }

func (f SchemaFragment) Wire() wire.Source {
	return wire.Source{Format: f.format.Wire(), Text: f.text}
}

// SchemaInspection contains native resolved declarations and expanded types.
// ResolvedSchema classifies and qualifies common/entity references; ExpandedSchema inlines common types.
type SchemaInspection struct {
	ResolvedSchema json.RawMessage       `json:"resolved_schema"`
	ExpandedSchema json.RawMessage       `json:"expanded_schema"`
	Ancestors      map[string][]string   `json:"ancestors"`
	Actions        []entityuid.EntityUID `json:"actions"`
	ActionGroups   []entityuid.EntityUID `json:"action_groups"`
	Environments   []RequestEnvironment  `json:"environments"`
}

// MarshalJSON preserves the flat UID form used by native schema results.
func (s SchemaInspection) MarshalJSON() ([]byte, error) {
	type inspection SchemaInspection
	return json.Marshal(struct {
		inspection
		Actions      []wire.UID `json:"actions"`
		ActionGroups []wire.UID `json:"action_groups"`
	}{inspection(s), entityuid.MetadataUIDs(s.Actions), entityuid.MetadataUIDs(s.ActionGroups)})
}

// ConvertSchemaFragment uses Cedar's native fragment conversions without resolving external declarations.
func (rt *Client) ConvertSchemaFragment(ctx context.Context, fragment SchemaFragment, format syntax.Format) (SchemaFragment, error) {
	if format != syntax.FormatCedar && format != syntax.FormatJSON {
		return SchemaFragment{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "invalid schema output format"}
	}
	var result struct {
		Fragment *wire.Source `json:"fragment"`
	}
	if err := rt.schemaOperation(ctx, struct {
		Op       string      `json:"op"`
		Fragment wire.Source `json:"fragment"`
		Format   string      `json:"format"`
	}{"convert", fragment.Wire(), format.Wire()}, &result); err != nil {
		return SchemaFragment{}, err
	}
	if result.Fragment == nil || result.Fragment.Format != format.Wire() {
		return SchemaFragment{}, diagnostic.FaultError(fmt.Errorf("schema conversion response has no requested fragment"))
	}
	return SchemaFragment{format: format, text: result.Fragment.Text}, nil
}

// ComposeSchema resolves references after Cedar combines all fragments.
// The JSON result retains declarations and can be used by all schema operations.
func (rt *Client) ComposeSchema(ctx context.Context, fragments ...SchemaFragment) (Schema, error) {
	sources := make([]wire.Source, len(fragments))
	for i, fragment := range fragments {
		sources[i] = fragment.Wire()
	}
	var result struct {
		Schema json.RawMessage `json:"schema"`
	}
	if err := rt.schemaOperation(ctx, struct {
		Op        string        `json:"op"`
		Fragments []wire.Source `json:"fragments"`
	}{"compose", sources}, &result); err != nil {
		return Schema{}, err
	}
	if !JsonObject(result.Schema) {
		return Schema{}, diagnostic.FaultError(fmt.Errorf("schema composition response has no schema object"))
	}
	return SchemaFromJSON(result.Schema), nil
}

// InspectSchema returns native type resolution, action applicability, and transitive entity hierarchy.
func (rt *Client) InspectSchema(ctx context.Context, schema Schema) (SchemaInspection, error) {
	var result struct {
		Inspection *SchemaInspection `json:"inspection"`
	}
	if err := rt.schemaOperation(ctx, struct {
		Op     string      `json:"op"`
		Schema wire.Source `json:"schema"`
	}{"inspect", schema.Wire()}, &result); err != nil {
		return SchemaInspection{}, err
	}
	if result.Inspection == nil || !JsonObject(result.Inspection.ResolvedSchema) || !JsonObject(result.Inspection.ExpandedSchema) || result.Inspection.Ancestors == nil || result.Inspection.Actions == nil || result.Inspection.ActionGroups == nil || result.Inspection.Environments == nil {
		return SchemaInspection{}, diagnostic.FaultError(fmt.Errorf("schema inspection response is incomplete"))
	}
	return *result.Inspection, nil
}
