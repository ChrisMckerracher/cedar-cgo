package policy

import (
	json "encoding/json"
	maps "maps"
)

// PolicyEffect identifies the effect declared by a policy.
type PolicyEffect string

const (
	Permit PolicyEffect = "permit"
	Forbid PolicyEffect = "forbid"
)

type parsedPolicyData struct {
	ID                    string            `json:"id"`
	Effect                PolicyEffect      `json:"effect"`
	Annotations           map[string]string `json:"annotations"`
	HasNonScopeConstraint bool              `json:"has_non_scope_constraint"`
	TemplateID            *string           `json:"template_id"`
	Cedar                 *string           `json:"cedar"`
	JSON                  json.RawMessage   `json:"json"`
}

// ParsedPolicy is an immutable Rust-validated policy snapshot, safe to share.
// Its zero value is invalid; create one through a Client.
type ParsedPolicy struct{ data *parsedPolicyData }

func (p ParsedPolicy) ID() string {
	if p.data == nil {
		return ""
	}
	return p.data.ID
}

func (p ParsedPolicy) Effect() PolicyEffect {
	if p.data == nil {
		return ""
	}
	return p.data.Effect
}

func (p ParsedPolicy) IsStatic() bool { return p.data != nil && p.data.TemplateID == nil }

func (p ParsedPolicy) TemplateID() (string, bool) {
	if p.data == nil || p.data.TemplateID == nil {
		return "", false
	}
	return *p.data.TemplateID, true
}

func (p ParsedPolicy) HasNonScopeConstraint() bool {
	return p.data != nil && p.data.HasNonScopeConstraint
}

func (p ParsedPolicy) Annotations() map[string]string {
	if p.data == nil {
		return nil
	}
	return maps.Clone(p.data.Annotations)
}

func (p ParsedPolicy) Annotation(key string) (string, bool) {
	if p.data == nil {
		return "", false
	}
	v, ok := p.data.Annotations[key]
	return v, ok
}
