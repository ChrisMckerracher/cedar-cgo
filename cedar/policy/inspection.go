package policy

import (
	json "encoding/json"
	maps "maps"
	slices "slices"
)

// PolicySyntax is an experimental, editable projection of the upstream PST for
// static policies. Expressions use Cedar JSON, not a Go expression language.
type PolicySyntax struct {
	ID          string            `json:"id"`
	Effect      PolicyEffect      `json:"effect"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Principal   ScopeConstraint   `json:"principal"`
	Action      ActionConstraint  `json:"action"`
	Resource    ScopeConstraint   `json:"resource"`
	Conditions  []PolicyCondition `json:"conditions,omitempty"`
}

type ParsedPolicyData struct {
	ID                    string            `json:"id"`
	Effect                PolicyEffect      `json:"effect"`
	Annotations           map[string]string `json:"annotations"`
	Principal             ScopeConstraint   `json:"principal"`
	Action                ActionConstraint  `json:"action"`
	Resource              ScopeConstraint   `json:"resource"`
	HasNonScopeConstraint bool              `json:"has_non_scope_constraint"`
	TemplateID            *string           `json:"template_id"`
	Cedar                 *string           `json:"cedar"`
	JSON                  json.RawMessage   `json:"json"`
	Syntax                *PolicySyntax     `json:"syntax"`
}

// ParsedPolicy is an immutable Rust-validated policy snapshot, safe to share.
// Its zero value is invalid; create one through a Runtime.
type ParsedPolicy struct{ data *ParsedPolicyData }

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

func CloneScope(c ScopeConstraint) ScopeConstraint {
	if c.Entity != nil {
		e := *c.Entity
		c.Entity = &e
	}
	return c
}

func CloneAction(c ActionConstraint) ActionConstraint {
	if c.Entity != nil {
		e := *c.Entity
		c.Entity = &e
	}
	c.Entities = slices.Clone(c.Entities)
	return c
}

func (p ParsedPolicy) PrincipalConstraint() ScopeConstraint {
	if p.data == nil {
		return ScopeConstraint{}
	}
	return CloneScope(p.data.Principal)
}

func (p ParsedPolicy) ResourceConstraint() ScopeConstraint {
	if p.data == nil {
		return ScopeConstraint{}
	}
	return CloneScope(p.data.Resource)
}

func (p ParsedPolicy) ActionConstraint() ActionConstraint {
	if p.data == nil {
		return ActionConstraint{}
	}
	return CloneAction(p.data.Action)
}
