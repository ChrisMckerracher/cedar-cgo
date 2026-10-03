package cedar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// SchemaFragment retains declarations that can reference other fragments.
// Parsing and resolution occur in the native Cedar module.
type SchemaFragment struct {
	format Format
	text   string
}

func SchemaFragmentFromCedar(text string) SchemaFragment {
	return SchemaFragment{format: FormatCedar, text: text}
}

func SchemaFragmentFromJSON(text []byte) SchemaFragment {
	return SchemaFragment{format: FormatJSON, text: string(text)}
}

func (f SchemaFragment) Format() Format { return f.format }
func (f SchemaFragment) Text() string   { return f.text }
func (f SchemaFragment) wire() wire.Source {
	return wire.Source{Format: f.format.wire(), Text: f.text}
}

// SchemaInspection contains native resolved declarations and expanded types.
// ResolvedSchema classifies and qualifies common/entity references; ExpandedSchema inlines common types.
type SchemaInspection struct {
	ResolvedSchema json.RawMessage      `json:"resolved_schema"`
	ExpandedSchema json.RawMessage      `json:"expanded_schema"`
	Ancestors      map[string][]string  `json:"ancestors"`
	Actions        []EntityUID          `json:"actions"`
	ActionGroups   []EntityUID          `json:"action_groups"`
	Environments   []RequestEnvironment `json:"environments"`
}

// MarshalJSON preserves the flat UID form used by native schema results.
func (s SchemaInspection) MarshalJSON() ([]byte, error) {
	uidList := func(entities []EntityUID) []wire.UID {
		if entities == nil {
			return nil
		}
		result := make([]wire.UID, len(entities))
		for i, entity := range entities {
			result[i] = entity.wire()
		}
		return result
	}
	type inspection SchemaInspection
	return json.Marshal(struct {
		inspection
		Actions      []wire.UID `json:"actions"`
		ActionGroups []wire.UID `json:"action_groups"`
	}{inspection(s), uidList(s.Actions), uidList(s.ActionGroups)})
}

// ConvertSchemaFragment uses Cedar's native fragment conversions without resolving external declarations.
func (rt *Runtime) ConvertSchemaFragment(ctx context.Context, fragment SchemaFragment, format Format) (SchemaFragment, error) {
	if format != FormatCedar && format != FormatJSON {
		return SchemaFragment{}, &Error{Kind: KindInput, Message: "invalid schema output format"}
	}
	var result struct {
		Fragment *wire.Source `json:"fragment"`
	}
	if err := rt.schemaOperation(ctx, struct {
		Op       string      `json:"op"`
		Fragment wire.Source `json:"fragment"`
		Format   string      `json:"format"`
	}{"convert", fragment.wire(), format.wire()}, &result); err != nil {
		return SchemaFragment{}, err
	}
	if result.Fragment == nil || result.Fragment.Format != format.wire() {
		return SchemaFragment{}, faultError(fmt.Errorf("schema conversion response has no requested fragment"))
	}
	return SchemaFragment{format: format, text: result.Fragment.Text}, nil
}

// ComposeSchema resolves references after Cedar combines all fragments.
// The JSON result retains declarations and can be used by all schema operations.
func (rt *Runtime) ComposeSchema(ctx context.Context, fragments ...SchemaFragment) (Schema, error) {
	sources := make([]wire.Source, len(fragments))
	for i, fragment := range fragments {
		sources[i] = fragment.wire()
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
	if !jsonObject(result.Schema) {
		return Schema{}, faultError(fmt.Errorf("schema composition response has no schema object"))
	}
	return SchemaFromJSON(result.Schema), nil
}

// InspectSchema returns native type resolution, action applicability, and transitive entity hierarchy.
func (rt *Runtime) InspectSchema(ctx context.Context, schema Schema) (SchemaInspection, error) {
	var result struct {
		Inspection *SchemaInspection `json:"inspection"`
	}
	if err := rt.schemaOperation(ctx, struct {
		Op     string      `json:"op"`
		Schema wire.Source `json:"schema"`
	}{"inspect", schema.wire()}, &result); err != nil {
		return SchemaInspection{}, err
	}
	if result.Inspection == nil || !jsonObject(result.Inspection.ResolvedSchema) || !jsonObject(result.Inspection.ExpandedSchema) || result.Inspection.Ancestors == nil || result.Inspection.Actions == nil || result.Inspection.ActionGroups == nil || result.Inspection.Environments == nil {
		return SchemaInspection{}, faultError(fmt.Errorf("schema inspection response is incomplete"))
	}
	return *result.Inspection, nil
}

// ActionEntities extracts native action entities with their transitive parent relationships.
func (rt *Runtime) ActionEntities(ctx context.Context, schema Schema) (Entities, error) {
	var result struct {
		Entities json.RawMessage `json:"entities"`
	}
	if err := rt.schemaOperation(ctx, struct {
		Op     string      `json:"op"`
		Schema wire.Source `json:"schema"`
	}{"actions", schema.wire()}, &result); err != nil {
		return Entities{}, err
	}
	var entities []json.RawMessage
	if err := json.Unmarshal(result.Entities, &entities); err != nil || entities == nil {
		return Entities{}, faultError(fmt.Errorf("schema action response has no entity array"))
	}
	return EntitiesFromJSON(result.Entities), nil
}

func (rt *Runtime) schemaOperation(ctx context.Context, input any, result any) error {
	in, err := json.Marshal(input)
	if err != nil {
		return &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return limitError("schema operation input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_schemas", in)
	if err != nil {
		return err
	}
	var envelope struct {
		Error *wire.Error `json:"error"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		return faultError(fmt.Errorf("decode schema operation response: %w", err))
	}
	if envelope.Error != nil {
		return moduleError(envelope.Error)
	}
	if err := json.Unmarshal(out, result); err != nil {
		return faultError(fmt.Errorf("decode schema operation result: %w", err))
	}
	return nil
}

func jsonObject(data json.RawMessage) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(data, &object) == nil && object != nil
}
