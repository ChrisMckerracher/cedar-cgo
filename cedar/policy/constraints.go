package policy

import (
	json "encoding/json"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
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
	Kind       ConstraintKind       `json:"kind"`
	Entity     *entityuid.EntityUID `json:"-"`
	EntityType string               `json:"entity_type,omitempty"`
}

// ActionConstraint uses Entity for eq and Entities for in (including an empty set).
type ActionConstraint struct {
	Kind     ConstraintKind        `json:"kind"`
	Entity   *entityuid.EntityUID  `json:"-"`
	Entities []entityuid.EntityUID `json:"-"`
}

type ScopeWire struct {
	Kind       ConstraintKind `json:"kind"`
	Entity     *wire.UID      `json:"entity,omitempty"`
	EntityType string         `json:"entity_type,omitempty"`
}

type ActionWire struct {
	Kind     ConstraintKind `json:"kind"`
	Entity   *wire.UID      `json:"entity,omitempty"`
	Entities *[]wire.UID    `json:"entities,omitempty"`
}

func PolicyUID(u *entityuid.EntityUID) *wire.UID {
	if u == nil {
		return nil
	}
	v := u.Wire()
	return &v
}

func FromPolicyUID(u *wire.UID) *entityuid.EntityUID {
	if u == nil {
		return nil
	}
	return &entityuid.EntityUID{Type: u.Type, ID: u.ID}
}

func (c ScopeConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(ScopeWire{c.Kind, PolicyUID(c.Entity), c.EntityType})
}

func (c *ScopeConstraint) UnmarshalJSON(b []byte) error {
	var w ScopeWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*c = ScopeConstraint{w.Kind, FromPolicyUID(w.Entity), w.EntityType}
	return nil
}

func (c ActionConstraint) MarshalJSON() ([]byte, error) {
	w := ActionWire{Kind: c.Kind, Entity: PolicyUID(c.Entity)}
	if c.Entities != nil || c.Kind == ConstraintIn {
		entities := make([]wire.UID, len(c.Entities))
		for i, e := range c.Entities {
			entities[i] = e.Wire()
		}
		w.Entities = &entities
	}
	return json.Marshal(w)
}

func (c *ActionConstraint) UnmarshalJSON(b []byte) error {
	var w ActionWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*c = ActionConstraint{Kind: w.Kind, Entity: FromPolicyUID(w.Entity)}
	if w.Entities != nil {
		c.Entities = make([]entityuid.EntityUID, len(*w.Entities))
		for i, e := range *w.Entities {
			c.Entities[i] = entityuid.EntityUID{Type: e.Type, ID: e.ID}
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
