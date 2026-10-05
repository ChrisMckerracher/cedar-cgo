package policy

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	utf8 "unicode/utf8"
)

// encoding/json replaces malformed UTF-8; reject it before it can change policy IDs or syntax.
func PolicyInputUTF8(input map[string]any) bool {
	valid := func(s string) bool { return utf8.ValidString(s) }
	validUID := func(u *entityuid.EntityUID) bool { return u == nil || (valid(u.Type) && valid(u.ID)) }
	validScope := func(s ScopeConstraint) bool {
		return valid(string(s.Kind)) && valid(s.EntityType) && validUID(s.Entity)
	}
	for _, value := range input {
		switch v := value.(type) {
		case string:
			if !valid(v) {
				return false
			}
		case bool:
			// Flag values carry no bytes; they are safe by construction.
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
		default:
			// Fail closed: an unchecked value type must never reach native execution.
			return false
		}
	}
	return true
}

func (rt *Client) policyCall(ctx context.Context, input map[string]any) (decoded PolicyOutput, decodeErr error) {
	var resp PolicyOutput
	if !PolicyInputUTF8(input) {
		return resp, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "policy operation input must be valid UTF-8"}
	}
	in, err := execution.Encode(input, "policy operation input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return resp, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	out, err := rt.runtime.CallOnce(ctx, "cgw_policies", in)
	if err != nil {
		return resp, err
	}
	if err = json.Unmarshal(out, &resp); err != nil {
		return resp, diagnostic.FaultError(fmt.Errorf("decode policy response: %w", err))
	}
	if resp.Error != nil {
		return resp, diagnostic.ModuleError(resp.Error)
	}
	if (resp.Policy == nil) == (resp.Set == nil) {
		return resp, diagnostic.FaultError(fmt.Errorf("policy response must contain exactly one result"))
	}
	return resp, nil
}

func (rt *Client) policy(ctx context.Context, input map[string]any) (ParsedPolicy, error) {
	out, err := rt.policyCall(ctx, input)
	if err != nil {
		return ParsedPolicy{}, err
	}
	if out.Policy == nil {
		return ParsedPolicy{}, diagnostic.FaultError(fmt.Errorf("policy response has no policy"))
	}
	return ParsedPolicy{out.Policy}, nil
}

func (rt *Client) policySet(ctx context.Context, input map[string]any) (ParsedPolicySet, map[string]string, error) {
	out, err := rt.policyCall(ctx, input)
	if err != nil {
		return ParsedPolicySet{}, nil, err
	}
	if out.Set == nil {
		return ParsedPolicySet{}, nil, diagnostic.FaultError(fmt.Errorf("policy response has no set"))
	}
	return ParsedPolicySet{out.Set}, out.Renames, nil
}

// ParsePolicy parses one static policy with the exact supplied ID (even empty).
func (rt *Client) ParsePolicy(ctx context.Context, id, source string) (ParsedPolicy, error) {
	return rt.policy(ctx, map[string]any{"op": "parse", "id": id, "source": wire.Source{Format: "cedar", Text: source}})
}

// PolicyFromJSON parses one static policy in Cedar JSON, with an explicit ID.
func (rt *Client) PolicyFromJSON(ctx context.Context, id string, source []byte) (ParsedPolicy, error) {
	return rt.policy(ctx, map[string]any{"op": "parse", "id": id, "source": wire.Source{Format: "json", Text: string(source)}})
}
