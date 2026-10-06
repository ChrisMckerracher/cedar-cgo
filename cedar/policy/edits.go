package policy

import (
	context "context"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
)

func (rt *Client) ParsePolicySet(ctx context.Context, source PolicySet) (ParsedPolicySet, error) {
	s, _, err := rt.policySet(ctx, map[string]any{"op": "inspect", "set": source.Wire()})
	return s, err
}

// AddPolicy returns a new set; duplicate IDs are errors from Rust. It accepts
// only static policies. All edit methods leave their inputs unchanged on errors.
func (rt *Client) AddPolicy(ctx context.Context, set PolicySet, policy ParsedPolicy) (ParsedPolicySet, error) {
	if policy.data == nil {
		return ParsedPolicySet{}, invalidParsedPolicy()
	}
	if !policy.IsStatic() {
		return ParsedPolicySet{}, &diagnostic.Error{Kind: diagnostic.KindPolicies, Message: "expected a static policy; use template linking to add a linked policy"}
	}
	s, _, err := rt.policySet(ctx, map[string]any{"op": "add", "set": set.Wire(), "id": policy.ID(), "policy": policy.JSON()})
	return s, err
}

// RemovePolicy removes a static policy. Missing IDs, template IDs, and linked
// policy IDs return Rust's remove_static error.
func (rt *Client) RemovePolicy(ctx context.Context, set PolicySet, id string) (ParsedPolicySet, error) {
	s, _, err := rt.policySet(ctx, map[string]any{"op": "remove", "set": set.Wire(), "id": id})
	return s, err
}

// MergePolicySets uses Rust's merge behavior, including its handling of equal
// policies. With renameDuplicates, the returned map records IDs Rust renamed.
func (rt *Client) MergePolicySets(ctx context.Context, set, other PolicySet, renameDuplicates bool) (ParsedPolicySet, map[string]string, error) {
	return rt.policySet(ctx, map[string]any{"op": "merge", "set": set.Wire(), "other": other.Wire(), "rename_duplicates": renameDuplicates})
}
