package applicability

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// PolicyApplicability lists native environments by policy and template ID.
// Native enumeration also preserves slot types for linked policies.
type PolicyApplicability struct {
	Policies  map[string][]cedarschema.RequestEnvironment `json:"policies"`
	Templates map[string][]cedarschema.RequestEnvironment `json:"templates"`
}

// ApplicableEnvironments invokes Cedar's native get_valid_request_envs operation.
// Results describe potential applicability, not decisions or satisfying requests.
func (rt *Client) ApplicableEnvironments(ctx context.Context, schema cedarschema.Schema, policies policy.PolicySet) (PolicyApplicability, error) {
	in, err := execution.Encode(struct {
		Schema   wire.Source `json:"schema"`
		Policies wire.Source `json:"policies"`
	}{schema.Wire(), policies.Wire()}, "applicability input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return PolicyApplicability{}, err
	}
	out, err := rt.runtime.CallOnce(ctx, "cgw_applicability", in)
	if err != nil {
		return PolicyApplicability{}, err
	}
	var result struct {
		Applicability *PolicyApplicability `json:"applicability"`
		Error         *wire.Error          `json:"error"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return PolicyApplicability{}, diagnostic.FaultError(fmt.Errorf("decode applicability response: %w", err))
	}
	if result.Error != nil {
		return PolicyApplicability{}, diagnostic.ModuleError(result.Error)
	}
	if result.Applicability == nil || result.Applicability.Policies == nil || result.Applicability.Templates == nil {
		return PolicyApplicability{}, diagnostic.FaultError(fmt.Errorf("applicability response has no maps"))
	}
	for _, entries := range []map[string][]cedarschema.RequestEnvironment{result.Applicability.Policies, result.Applicability.Templates} {
		for _, envs := range entries {
			if envs == nil {
				return PolicyApplicability{}, diagnostic.FaultError(fmt.Errorf("applicability response has a null environment list"))
			}
			for _, env := range envs {
				if env.PrincipalType == "" || env.ResourceType == "" || env.Action.Type == "" || (env.PrincipalSlotType != nil && *env.PrincipalSlotType == "") || (env.ResourceSlotType != nil && *env.ResourceSlotType == "") {
					return PolicyApplicability{}, diagnostic.FaultError(fmt.Errorf("applicability response has an incomplete environment"))
				}
			}
		}
	}
	return *result.Applicability, nil
}
