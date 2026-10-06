package policy

import (
	context "context"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

func (rt *Client) policyCall(ctx context.Context, input map[string]any) (decoded policyOutput, decodeErr error) {
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	resp, err := execution.Exchange[policyOutput](ctx, rt.runtime, "cgw_policies", "policy operation", input)
	if err != nil {
		return policyOutput{}, err
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

// ParsePolicy parses one static policy with the exact supplied ID, including an empty ID.
func (rt *Client) ParsePolicy(ctx context.Context, id, source string) (ParsedPolicy, error) {
	return rt.policy(ctx, map[string]any{"op": "parse", "id": id, "source": wire.Source{Format: "cedar", Text: source}})
}

// PolicyFromJSON parses one static policy in Cedar JSON with an explicit ID.
func (rt *Client) PolicyFromJSON(ctx context.Context, id string, source []byte) (ParsedPolicy, error) {
	return rt.policy(ctx, map[string]any{"op": "parse", "id": id, "source": wire.Source{Format: "json", Text: string(source)}})
}
