package template

import (
	context "context"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// AddTemplate returns a new set with the template under templateID. Rust rejects
// static policies and duplicate IDs. The input set is unchanged, including on error.
func (rt *Client) AddTemplate(ctx context.Context, policies policy.PolicySet, templateID string, template Template) (policy.PolicySet, error) {
	return rt.editTemplates(ctx, policies, struct {
		Op       string      `json:"op"`
		ID       string      `json:"id"`
		Template wire.Source `json:"template"`
	}{"add", templateID, wire.Source{Format: template.format.Wire(), Text: template.text}})
}

// LinkTemplate returns a new set containing the linked policy. Bindings must
// exactly match the template's slots; a nil map means no bindings.
func (rt *Client) LinkTemplate(ctx context.Context, policies policy.PolicySet, templateID, policyID string, bindings SlotBindings) (policy.PolicySet, error) {
	values := make(map[SlotID]wire.UID, len(bindings))
	for slot, uid := range bindings {
		values[slot] = uid.Wire()
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
func (rt *Client) UnlinkTemplate(ctx context.Context, policies policy.PolicySet, policyID string) (policy.PolicySet, error) {
	return rt.editTemplates(ctx, policies, struct {
		Op       string `json:"op"`
		PolicyID string `json:"policy_id"`
	}{"unlink", policyID})
}

// RemoveTemplate returns a new set without the template. Rust rejects removal
// while links remain, or when templateID does not identify a template.
func (rt *Client) RemoveTemplate(ctx context.Context, policies policy.PolicySet, templateID string) (policy.PolicySet, error) {
	return rt.editTemplates(ctx, policies, struct {
		Op         string `json:"op"`
		TemplateID string `json:"template_id"`
	}{"remove", templateID})
}

// Templates returns templates sorted by ID, with slots sorted by name.
func (rt *Client) Templates(ctx context.Context, policies policy.PolicySet) ([]TemplateInfo, error) {
	resp, err := rt.templateCall(ctx, policies, struct {
		Op string `json:"op"`
	}{"templates"})
	if err != nil {
		return nil, err
	}
	if resp.Templates == nil {
		return nil, diagnostic.FaultError(fmt.Errorf("template response has no templates"))
	}
	return *resp.Templates, nil
}

// TemplateLinks returns linked policies sorted by policy ID; static policies are omitted.
func (rt *Client) TemplateLinks(ctx context.Context, policies policy.PolicySet) (decoded []TemplateLink, decodeErr error) {
	resp, err := rt.templateCall(ctx, policies, struct {
		Op string `json:"op"`
	}{"links"})
	if err != nil {
		return nil, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	if resp.Links == nil {
		return nil, diagnostic.FaultError(fmt.Errorf("template response has no links"))
	}
	links := make([]TemplateLink, len(*resp.Links))
	for i, link := range *resp.Links {
		bindings := make(SlotBindings, len(link.Bindings))
		for slot, uid := range link.Bindings {
			bindings[slot] = entityuid.NewEntityUID(uid.Type, uid.ID)
		}
		links[i] = TemplateLink{PolicyID: link.PolicyID, TemplateID: link.TemplateID, Bindings: bindings}
	}
	return links, nil
}
