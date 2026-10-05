package policy

import (
	bytes "bytes"
	json "encoding/json"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	maps "maps"
	slices "slices"
)

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
		return "", InvalidParsedPolicy()
	}
	if p.data.Cedar == nil {
		return "", &diagnostic.Error{Kind: diagnostic.KindPolicies, Message: "linked policies cannot be rendered as Cedar while preserving links"}
	}
	return *p.data.Cedar, nil
}

// Syntax returns an independent editable copy. Linked policies must be edited
// through their template; they return a KindPolicies error here.
func (p ParsedPolicy) Syntax() (PolicySyntax, error) {
	if p.data == nil {
		return PolicySyntax{}, InvalidParsedPolicy()
	}
	if p.data.Syntax == nil {
		return PolicySyntax{}, &diagnostic.Error{Kind: diagnostic.KindPolicies, Message: "linked policies do not have static policy syntax"}
	}
	s := *p.data.Syntax
	s.Annotations = maps.Clone(s.Annotations)
	s.Principal = CloneScope(s.Principal)
	s.Resource = CloneScope(s.Resource)
	s.Action = CloneAction(s.Action)
	s.Conditions = slices.Clone(s.Conditions)
	for i := range s.Conditions {
		s.Conditions[i].Body = bytes.Clone(s.Conditions[i].Body)
	}
	return s, nil
}

func InvalidParsedPolicy() *diagnostic.Error {
	return &diagnostic.Error{Kind: diagnostic.KindInput, Message: "zero ParsedPolicy is invalid"}
}

type ParsedSetData struct {
	JSON     json.RawMessage    `json:"json"`
	Cedar    *string            `json:"cedar"`
	Policies []ParsedPolicyData `json:"policies"`
}

// ParsedPolicySet is an immutable parsed snapshot. Its zero value is an empty set.
// Templates and links are preserved in JSON and Source; Policies includes static
// and linked policies, but not templates.
type ParsedPolicySet struct{ data *ParsedSetData }

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
	i, ok := slices.BinarySearchFunc(s.data.Policies, id, func(p ParsedPolicyData, id string) int {
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
		return "", &diagnostic.Error{Kind: diagnostic.KindPolicies, Message: "policy set contains linked policies; use JSON to preserve links"}
	}
	return *s.data.Cedar, nil
}

type PolicyOutput struct {
	Policy  *ParsedPolicyData `json:"policy"`
	Set     *ParsedSetData    `json:"set"`
	Renames map[string]string `json:"renames"`
	Error   *wire.Error       `json:"error"`
}
