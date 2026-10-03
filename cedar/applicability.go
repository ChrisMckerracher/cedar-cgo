package cedar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// RequestEnvironment describes a schema principal/action/resource combination.
// It describes potential applicability, without granting authorization.
type RequestEnvironment struct {
	PrincipalType     string    `json:"principal_type"`
	Action            EntityUID `json:"action"`
	ResourceType      string    `json:"resource_type"`
	PrincipalSlotType *string   `json:"principal_slot_type,omitempty"`
	ResourceSlotType  *string   `json:"resource_slot_type,omitempty"`
}

// MarshalJSON preserves the flat UID fields used by native applicability metadata.
func (env RequestEnvironment) MarshalJSON() ([]byte, error) {
	if err := wire.CheckUTF8(env.PrincipalType, env.ResourceType); err != nil {
		return nil, err
	}
	for _, slot := range []*string{env.PrincipalSlotType, env.ResourceSlotType} {
		if slot != nil {
			if err := wire.CheckUTF8(*slot); err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(struct {
		PrincipalType     string   `json:"principal_type"`
		Action            wire.UID `json:"action"`
		ResourceType      string   `json:"resource_type"`
		PrincipalSlotType *string  `json:"principal_slot_type,omitempty"`
		ResourceSlotType  *string  `json:"resource_slot_type,omitempty"`
	}{env.PrincipalType, env.Action.wire(), env.ResourceType, env.PrincipalSlotType, env.ResourceSlotType})
}

// PolicyApplicability lists native environments by policy and template ID.
// Native enumeration also preserves slot types for linked policies.
type PolicyApplicability struct {
	Policies  map[string][]RequestEnvironment `json:"policies"`
	Templates map[string][]RequestEnvironment `json:"templates"`
}

// ApplicableEnvironments invokes Cedar's native get_valid_request_envs operation.
// Results describe potential applicability, not decisions or satisfying requests.
func (rt *Runtime) ApplicableEnvironments(ctx context.Context, schema Schema, policies PolicySet) (PolicyApplicability, error) {
	in, err := json.Marshal(struct {
		Schema   wire.Source `json:"schema"`
		Policies wire.Source `json:"policies"`
	}{schema.wire(), policies.wire()})
	if err != nil {
		return PolicyApplicability{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return PolicyApplicability{}, limitError("applicability input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_applicability", in)
	if err != nil {
		return PolicyApplicability{}, err
	}
	var result struct {
		Applicability *PolicyApplicability `json:"applicability"`
		Error         *wire.Error          `json:"error"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return PolicyApplicability{}, faultError(fmt.Errorf("decode applicability response: %w", err))
	}
	if result.Error != nil {
		return PolicyApplicability{}, moduleError(result.Error)
	}
	if result.Applicability == nil || result.Applicability.Policies == nil || result.Applicability.Templates == nil {
		return PolicyApplicability{}, faultError(fmt.Errorf("applicability response has no maps"))
	}
	for _, entries := range []map[string][]RequestEnvironment{result.Applicability.Policies, result.Applicability.Templates} {
		for _, envs := range entries {
			if envs == nil {
				return PolicyApplicability{}, faultError(fmt.Errorf("applicability response has a null environment list"))
			}
			for _, env := range envs {
				if env.PrincipalType == "" || env.ResourceType == "" || env.Action.Type == "" || (env.PrincipalSlotType != nil && *env.PrincipalSlotType == "") || (env.ResourceSlotType != nil && *env.ResourceSlotType == "") {
					return PolicyApplicability{}, faultError(fmt.Errorf("applicability response has an incomplete environment"))
				}
			}
		}
	}
	return *result.Applicability, nil
}
