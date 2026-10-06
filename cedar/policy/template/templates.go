package template

import (
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// Template is an immutable template source, parsed by Rust when added to a set.
// Template management is experimental and may change in a minor release.
type Template struct {
	format syntax.Format
	text   string
}

func TemplateFromCedar(text string) Template {
	return Template{format: syntax.FormatCedar, text: text}
}

func TemplateFromJSON(text []byte) Template {
	return Template{format: syntax.FormatJSON, text: string(text)}
}

func (t Template) Format() syntax.Format { return t.format }

func (t Template) Text() string { return t.text }

// SlotID identifies a template slot; Rust rejects unsupported slot names.
type SlotID string

const (
	PrincipalSlot SlotID = "?principal"
	ResourceSlot  SlotID = "?resource"
)

type SlotBindings map[SlotID]entityuid.EntityUID

// TemplateInfo describes a template independently of any native state.
// JSON is Cedar's template EST representation; Cedar is its human-readable rendering.
type TemplateInfo struct {
	ID          string            `json:"id"`
	Cedar       string            `json:"cedar"`
	JSON        json.RawMessage   `json:"json"`
	Slots       []SlotID          `json:"slots"`
	Annotations map[string]string `json:"annotations"`
}

// TemplateLink retains the link's identity and bindings, not a flattened static policy.
type TemplateLink struct {
	PolicyID   string
	TemplateID string
	Bindings   SlotBindings
}

type templateInput struct {
	Policies  wire.Source `json:"policies"`
	Operation any         `json:"operation"`
}

type templateOutput struct {
	Policies  json.RawMessage `json:"policies"`
	Templates *[]TemplateInfo `json:"templates"`
	Links     *[]struct {
		PolicyID   string              `json:"policy_id"`
		TemplateID string              `json:"template_id"`
		Bindings   map[SlotID]wire.UID `json:"bindings"`
	} `json:"links"`
	wire.Response
}

func (rt *Client) templateCall(ctx context.Context, policies policy.PolicySet, op any) (templateOutput, error) {
	return execution.Exchange[templateOutput](ctx, rt.runtime, "cgw_templates", "template", templateInput{Policies: policies.Wire(), Operation: op})
}

func (rt *Client) editTemplates(ctx context.Context, policies policy.PolicySet, op any) (policy.PolicySet, error) {
	resp, err := rt.templateCall(ctx, policies, op)
	if err != nil {
		return policy.PolicySet{}, err
	}
	if len(resp.Policies) == 0 || resp.Policies[0] != '{' {
		return policy.PolicySet{}, diagnostic.FaultError(fmt.Errorf("template response has no policy set"))
	}
	return policy.PoliciesFromJSON(resp.Policies), nil
}
