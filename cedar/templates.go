package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Template is an immutable template source, parsed by Rust when added to a set.
// Template management is experimental and may change in a minor release.
type Template struct {
	format Format
	text   string
}

func TemplateFromCedar(text string) Template { return Template{format: FormatCedar, text: text} }

func TemplateFromJSON(text []byte) Template { return Template{format: FormatJSON, text: string(text)} }

func (t Template) Format() Format { return t.format }
func (t Template) Text() string   { return t.text }

// SlotID identifies a template slot; Rust rejects unsupported slot names.
type SlotID string

const (
	PrincipalSlot SlotID = "?principal"
	ResourceSlot  SlotID = "?resource"
)

type SlotBindings map[SlotID]EntityUID

// TemplateInfo describes a template independently of any guest instance.
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
	Error *wire.Error `json:"error"`
}

func templateUTF8(texts ...string) error {
	for _, text := range texts {
		if !utf8.ValidString(text) {
			return &Error{Kind: KindInput, Message: "template input is not valid UTF-8"}
		}
	}
	return nil
}

func (rt *Runtime) templateCall(ctx context.Context, policies PolicySet, op any) (templateOutput, error) {
	if err := templateUTF8(policies.text); err != nil {
		return templateOutput{}, err
	}
	in, err := json.Marshal(templateInput{Policies: policies.wire(), Operation: op})
	if err != nil {
		return templateOutput{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return templateOutput{}, limitError("template input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_templates", in)
	if err != nil {
		return templateOutput{}, err
	}
	var resp templateOutput
	if err := json.Unmarshal(out, &resp); err != nil {
		return templateOutput{}, faultError(fmt.Errorf("decode template response: %w", err))
	}
	if resp.Error != nil {
		return templateOutput{}, moduleError(resp.Error)
	}
	return resp, nil
}

func (rt *Runtime) editTemplates(ctx context.Context, policies PolicySet, op any) (PolicySet, error) {
	resp, err := rt.templateCall(ctx, policies, op)
	if err != nil {
		return PolicySet{}, err
	}
	if len(resp.Policies) == 0 || resp.Policies[0] != '{' {
		return PolicySet{}, faultError(fmt.Errorf("template response has no policy set"))
	}
	return PoliciesFromJSON(resp.Policies), nil
}

// AddTemplate returns a new set with the template under templateID. Rust rejects
// static policies and duplicate IDs. The input set is unchanged, including on error.
func (rt *Runtime) AddTemplate(ctx context.Context, policies PolicySet, templateID string, template Template) (PolicySet, error) {
	if err := templateUTF8(templateID, template.text); err != nil {
		return PolicySet{}, err
	}
	return rt.editTemplates(ctx, policies, struct {
		Op       string      `json:"op"`
		ID       string      `json:"id"`
		Template wire.Source `json:"template"`
	}{"add", templateID, wire.Source{Format: template.format.wire(), Text: template.text}})
}

// LinkTemplate returns a new set containing the linked policy. Bindings must
// exactly match the template's slots; a nil map means no bindings.
func (rt *Runtime) LinkTemplate(ctx context.Context, policies PolicySet, templateID, policyID string, bindings SlotBindings) (PolicySet, error) {
	if err := templateUTF8(templateID, policyID); err != nil {
		return PolicySet{}, err
	}
	values := make(map[SlotID]wire.UID, len(bindings))
	for slot, uid := range bindings {
		if err := templateUTF8(string(slot), uid.Type, uid.ID); err != nil {
			return PolicySet{}, err
		}
		values[slot] = uid.wire()
	}
	return rt.editTemplates(ctx, policies, struct {
		Op         string              `json:"op"`
		TemplateID string              `json:"template_id"`
		PolicyID   string              `json:"policy_id"`
		Bindings   map[SlotID]wire.UID `json:"bindings"`
	}{"link", templateID, policyID, values})
}

// UnlinkTemplate returns a new set without the linked policy. The template remains.
// Rust rejects IDs of templates, static policies, and missing policies.
func (rt *Runtime) UnlinkTemplate(ctx context.Context, policies PolicySet, policyID string) (PolicySet, error) {
	if err := templateUTF8(policyID); err != nil {
		return PolicySet{}, err
	}
	return rt.editTemplates(ctx, policies, struct {
		Op       string `json:"op"`
		PolicyID string `json:"policy_id"`
	}{"unlink", policyID})
}

// RemoveTemplate returns a new set without the template. Rust rejects removal
// while links remain, or when templateID does not identify a template.
func (rt *Runtime) RemoveTemplate(ctx context.Context, policies PolicySet, templateID string) (PolicySet, error) {
	if err := templateUTF8(templateID); err != nil {
		return PolicySet{}, err
	}
	return rt.editTemplates(ctx, policies, struct {
		Op         string `json:"op"`
		TemplateID string `json:"template_id"`
	}{"remove", templateID})
}

// Templates returns templates sorted by ID, with slots sorted by name.
func (rt *Runtime) Templates(ctx context.Context, policies PolicySet) ([]TemplateInfo, error) {
	resp, err := rt.templateCall(ctx, policies, struct {
		Op string `json:"op"`
	}{"templates"})
	if err != nil {
		return nil, err
	}
	if resp.Templates == nil {
		return nil, faultError(fmt.Errorf("template response has no templates"))
	}
	return *resp.Templates, nil
}

// TemplateLinks returns linked policies sorted by policy ID; static policies are omitted.
func (rt *Runtime) TemplateLinks(ctx context.Context, policies PolicySet) ([]TemplateLink, error) {
	resp, err := rt.templateCall(ctx, policies, struct {
		Op string `json:"op"`
	}{"links"})
	if err != nil {
		return nil, err
	}
	if resp.Links == nil {
		return nil, faultError(fmt.Errorf("template response has no links"))
	}
	links := make([]TemplateLink, len(*resp.Links))
	for i, link := range *resp.Links {
		bindings := make(SlotBindings, len(link.Bindings))
		for slot, uid := range link.Bindings {
			bindings[slot] = NewEntityUID(uid.Type, uid.ID)
		}
		links[i] = TemplateLink{PolicyID: link.PolicyID, TemplateID: link.TemplateID, Bindings: bindings}
	}
	return links, nil
}
