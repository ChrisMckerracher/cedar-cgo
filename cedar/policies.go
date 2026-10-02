package cedar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"unicode/utf8"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// PolicyEffect is the effect declared by a policy, independent of its evaluation.
type PolicyEffect string

const (
	Permit PolicyEffect = "permit"
	Forbid PolicyEffect = "forbid"
)

type ConstraintKind string

const (
	ConstraintAny  ConstraintKind = "any"
	ConstraintEq   ConstraintKind = "eq"
	ConstraintIn   ConstraintKind = "in"
	ConstraintIs   ConstraintKind = "is"
	ConstraintIsIn ConstraintKind = "is_in"
)

// ScopeConstraint describes a principal or resource constraint. Entity is used by
// eq/in/is_in; EntityType by is/is_in. Unused fields must be empty.
type ScopeConstraint struct {
	Kind       ConstraintKind `json:"kind"`
	Entity     *EntityUID     `json:"-"`
	EntityType string         `json:"entity_type,omitempty"`
}

// ActionConstraint uses Entity for eq and Entities for in (including an empty set).
type ActionConstraint struct {
	Kind     ConstraintKind `json:"kind"`
	Entity   *EntityUID     `json:"-"`
	Entities []EntityUID    `json:"-"`
}

type scopeWire struct {
	Kind       ConstraintKind `json:"kind"`
	Entity     *wire.UID      `json:"entity,omitempty"`
	EntityType string         `json:"entity_type,omitempty"`
}

type actionWire struct {
	Kind     ConstraintKind `json:"kind"`
	Entity   *wire.UID      `json:"entity,omitempty"`
	Entities *[]wire.UID    `json:"entities,omitempty"`
}

func policyUID(u *EntityUID) *wire.UID {
	if u == nil {
		return nil
	}
	v := u.wire()
	return &v
}
func fromPolicyUID(u *wire.UID) *EntityUID {
	if u == nil {
		return nil
	}
	return &EntityUID{Type: u.Type, ID: u.ID}
}

func (c ScopeConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(scopeWire{c.Kind, policyUID(c.Entity), c.EntityType})
}
func (c *ScopeConstraint) UnmarshalJSON(b []byte) error {
	var w scopeWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*c = ScopeConstraint{w.Kind, fromPolicyUID(w.Entity), w.EntityType}
	return nil
}
func (c ActionConstraint) MarshalJSON() ([]byte, error) {
	w := actionWire{Kind: c.Kind, Entity: policyUID(c.Entity)}
	if c.Entities != nil || c.Kind == ConstraintIn {
		entities := make([]wire.UID, len(c.Entities))
		for i, e := range c.Entities {
			entities[i] = e.wire()
		}
		w.Entities = &entities
	}
	return json.Marshal(w)
}
func (c *ActionConstraint) UnmarshalJSON(b []byte) error {
	var w actionWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*c = ActionConstraint{Kind: w.Kind, Entity: fromPolicyUID(w.Entity)}
	if w.Entities != nil {
		c.Entities = make([]EntityUID, len(*w.Entities))
		for i, e := range *w.Entities {
			c.Entities[i] = EntityUID{Type: e.Type, ID: e.ID}
		}
	}
	return nil
}

// PolicyCondition preserves clause order and kind ("when" or "unless"). Body is
// an expression in Cedar's JSON policy format, interpreted only by Rust.
type PolicyCondition struct {
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

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

type parsedPolicyData struct {
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

func cloneScope(c ScopeConstraint) ScopeConstraint {
	if c.Entity != nil {
		e := *c.Entity
		c.Entity = &e
	}
	return c
}
func cloneAction(c ActionConstraint) ActionConstraint {
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
	return cloneScope(p.data.Principal)
}
func (p ParsedPolicy) ResourceConstraint() ScopeConstraint {
	if p.data == nil {
		return ScopeConstraint{}
	}
	return cloneScope(p.data.Resource)
}
func (p ParsedPolicy) ActionConstraint() ActionConstraint {
	if p.data == nil {
		return ActionConstraint{}
	}
	return cloneAction(p.data.Action)
}

// JSON returns the individual policy's Cedar JSON. It carries neither the policy
// ID nor template links; persist ParsedPolicySet.JSON to retain that information.
func (p ParsedPolicy) JSON() json.RawMessage {
	if p.data == nil {
		return nil
	}
	return bytes.Clone(p.data.JSON)
}

// Cedar returns Cedar syntax without the policy ID. Linked policies cannot be
// represented with their links and return a KindPolicies error.
func (p ParsedPolicy) Cedar() (string, error) {
	if p.data == nil {
		return "", invalidParsedPolicy()
	}
	if p.data.Cedar == nil {
		return "", &Error{Kind: KindPolicies, Message: "linked policies cannot be rendered as Cedar while preserving links"}
	}
	return *p.data.Cedar, nil
}

// Syntax returns an independent editable copy. Linked policies must be edited
// through their template; they return a KindPolicies error here.
func (p ParsedPolicy) Syntax() (PolicySyntax, error) {
	if p.data == nil {
		return PolicySyntax{}, invalidParsedPolicy()
	}
	if p.data.Syntax == nil {
		return PolicySyntax{}, &Error{Kind: KindPolicies, Message: "linked policies do not have static policy syntax"}
	}
	s := *p.data.Syntax
	s.Annotations = maps.Clone(s.Annotations)
	s.Principal = cloneScope(s.Principal)
	s.Resource = cloneScope(s.Resource)
	s.Action = cloneAction(s.Action)
	s.Conditions = slices.Clone(s.Conditions)
	for i := range s.Conditions {
		s.Conditions[i].Body = bytes.Clone(s.Conditions[i].Body)
	}
	return s, nil
}

func invalidParsedPolicy() *Error {
	return &Error{Kind: KindInput, Message: "zero ParsedPolicy is invalid"}
}

type parsedSetData struct {
	JSON     json.RawMessage    `json:"json"`
	Cedar    *string            `json:"cedar"`
	Policies []parsedPolicyData `json:"policies"`
}

// ParsedPolicySet is an immutable parsed snapshot. Its zero value is an empty set.
// Templates and links are preserved in JSON and Source; Policies includes static
// and linked policies, but not templates.
type ParsedPolicySet struct{ data *parsedSetData }

func (s ParsedPolicySet) JSON() json.RawMessage {
	if s.data == nil {
		return json.RawMessage(`{"templates":{},"staticPolicies":{},"templateLinks":[]}`)
	}
	return bytes.Clone(s.data.JSON)
}
func (s ParsedPolicySet) Source() PolicySet { return PoliciesFromJSON(s.JSON()) }
func (s ParsedPolicySet) Policies() []ParsedPolicy {
	if s.data == nil {
		return nil
	}
	out := make([]ParsedPolicy, len(s.data.Policies))
	for i := range out {
		out[i] = ParsedPolicy{&s.data.Policies[i]}
	}
	return out
}
func (s ParsedPolicySet) Policy(id string) (ParsedPolicy, bool) {
	if s.data == nil {
		return ParsedPolicy{}, false
	}
	i, ok := slices.BinarySearchFunc(s.data.Policies, id, func(p parsedPolicyData, id string) int {
		if p.ID < id {
			return -1
		}
		if p.ID > id {
			return 1
		}
		return 0
	})
	if !ok {
		return ParsedPolicy{}, false
	}
	return ParsedPolicy{&s.data.Policies[i]}, true
}

// Cedar renders policies sorted by ID, followed by templates sorted by ID. It
// loses IDs and rejects linked policies; use JSON for lossless set persistence.
func (s ParsedPolicySet) Cedar() (string, error) {
	if s.data == nil {
		return "", nil
	}
	if s.data.Cedar == nil {
		return "", &Error{Kind: KindPolicies, Message: "policy set contains linked policies; use JSON to preserve links"}
	}
	return *s.data.Cedar, nil
}

type policyOutput struct {
	Policy  *parsedPolicyData `json:"policy"`
	Set     *parsedSetData    `json:"set"`
	Renames map[string]string `json:"renames"`
	Error   *wire.Error       `json:"error"`
}

// encoding/json replaces malformed UTF-8; reject it before it can change policy IDs or syntax.
func policyInputUTF8(input map[string]any) bool {
	valid := func(s string) bool { return utf8.ValidString(s) }
	validUID := func(u *EntityUID) bool { return u == nil || (valid(u.Type) && valid(u.ID)) }
	validScope := func(s ScopeConstraint) bool {
		return valid(string(s.Kind)) && valid(s.EntityType) && validUID(s.Entity)
	}
	for _, value := range input {
		switch v := value.(type) {
		case string:
			if !valid(v) {
				return false
			}
		case wire.Source:
			if !valid(v.Text) {
				return false
			}
		case json.RawMessage:
			if !utf8.Valid(v) {
				return false
			}
		case PolicySyntax:
			if !valid(v.ID) || !valid(string(v.Effect)) || !validScope(v.Principal) || !validScope(v.Resource) || !valid(string(v.Action.Kind)) || !validUID(v.Action.Entity) {
				return false
			}
			for _, e := range v.Action.Entities {
				if !validUID(&e) {
					return false
				}
			}
			for k, a := range v.Annotations {
				if !valid(k) || !valid(a) {
					return false
				}
			}
			for _, c := range v.Conditions {
				if !valid(c.Kind) || !utf8.Valid(c.Body) {
					return false
				}
			}
		}
	}
	return true
}

func (rt *Runtime) policyCall(ctx context.Context, input map[string]any) (policyOutput, error) {
	var resp policyOutput
	if !policyInputUTF8(input) {
		return resp, &Error{Kind: KindInput, Message: "policy operation input must be valid UTF-8"}
	}
	in, err := json.Marshal(input)
	if err != nil {
		return resp, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return resp, limitError("policy operation input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_policies", in)
	if err != nil {
		return resp, err
	}
	if err = json.Unmarshal(out, &resp); err != nil {
		return resp, faultError(fmt.Errorf("decode policy response: %w", err))
	}
	if resp.Error != nil {
		return resp, moduleError(resp.Error)
	}
	if (resp.Policy == nil) == (resp.Set == nil) {
		return resp, faultError(fmt.Errorf("policy response must contain exactly one result"))
	}
	return resp, nil
}
func (rt *Runtime) policy(ctx context.Context, input map[string]any) (ParsedPolicy, error) {
	out, err := rt.policyCall(ctx, input)
	if err != nil {
		return ParsedPolicy{}, err
	}
	if out.Policy == nil {
		return ParsedPolicy{}, faultError(fmt.Errorf("policy response has no policy"))
	}
	return ParsedPolicy{out.Policy}, nil
}
func (rt *Runtime) policySet(ctx context.Context, input map[string]any) (ParsedPolicySet, map[string]string, error) {
	out, err := rt.policyCall(ctx, input)
	if err != nil {
		return ParsedPolicySet{}, nil, err
	}
	if out.Set == nil {
		return ParsedPolicySet{}, nil, faultError(fmt.Errorf("policy response has no set"))
	}
	return ParsedPolicySet{out.Set}, out.Renames, nil
}

// ParsePolicy parses one static policy with the exact supplied ID (even empty).
func (rt *Runtime) ParsePolicy(ctx context.Context, id, source string) (ParsedPolicy, error) {
	return rt.policy(ctx, map[string]any{"op": "parse", "id": id, "source": wire.Source{Format: "cedar", Text: source}})
}

// PolicyFromJSON parses one static policy in Cedar JSON, with an explicit ID.
func (rt *Runtime) PolicyFromJSON(ctx context.Context, id string, source []byte) (ParsedPolicy, error) {
	return rt.policy(ctx, map[string]any{"op": "parse", "id": id, "source": wire.Source{Format: "json", Text: string(source)}})
}

// PolicyFromSyntax constructs a static policy through upstream PST validation.
// This API is experimental, and may change with Cedar's PST representation.
func (rt *Runtime) PolicyFromSyntax(ctx context.Context, syntax PolicySyntax) (ParsedPolicy, error) {
	return rt.policy(ctx, map[string]any{"op": "construct", "syntax": syntax})
}
func (rt *Runtime) ParsePolicySet(ctx context.Context, source PolicySet) (ParsedPolicySet, error) {
	s, _, err := rt.policySet(ctx, map[string]any{"op": "inspect", "set": source.wire()})
	return s, err
}

// AddPolicy returns a new set; duplicate IDs are errors from Rust. It accepts
// only static policies. All edit methods leave their inputs unchanged on errors.
func (rt *Runtime) AddPolicy(ctx context.Context, set PolicySet, policy ParsedPolicy) (ParsedPolicySet, error) {
	if policy.data == nil {
		return ParsedPolicySet{}, invalidParsedPolicy()
	}
	if !policy.IsStatic() {
		return ParsedPolicySet{}, &Error{Kind: KindPolicies, Message: "expected a static policy; use template linking to add a linked policy"}
	}
	s, _, err := rt.policySet(ctx, map[string]any{"op": "add", "set": set.wire(), "id": policy.ID(), "policy": policy.JSON()})
	return s, err
}

// RemovePolicy removes a static policy. Missing IDs, template IDs, and linked
// policy IDs return Rust's remove_static error.
func (rt *Runtime) RemovePolicy(ctx context.Context, set PolicySet, id string) (ParsedPolicySet, error) {
	s, _, err := rt.policySet(ctx, map[string]any{"op": "remove", "set": set.wire(), "id": id})
	return s, err
}

// MergePolicySets uses Rust's merge behavior, including its handling of equal
// policies. With renameDuplicates, the returned map records IDs Rust renamed.
func (rt *Runtime) MergePolicySets(ctx context.Context, set, other PolicySet, renameDuplicates bool) (ParsedPolicySet, map[string]string, error) {
	return rt.policySet(ctx, map[string]any{"op": "merge", "set": set.wire(), "other": other.wire(), "rename_duplicates": renameDuplicates})
}
