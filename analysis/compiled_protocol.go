package analysis

import (
	"encoding/json"
	"errors"
	"fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type compiledEnvironment struct {
	PrincipalType string   `json:"principal_type"`
	Action        wire.UID `json:"action"`
	ResourceType  string   `json:"resource_type"`
}

type compiledInput struct {
	Operation    string                 `json:"operation"`
	Schema       *wire.Source           `json:"schema,omitempty"`
	Environments *[]compiledEnvironment `json:"environments,omitempty"`
	Policies     *wire.Source           `json:"policies,omitempty"`
	First        uint64                 `json:"first,omitempty"`
	Second       uint64                 `json:"second,omitempty"`
	Handle       uint64                 `json:"handle,omitempty"`
	Query        string                 `json:"query,omitempty"`
}

func (a *Analyzer) encodeCompiled(input compiledInput) ([]byte, error) {
	if input.Environments != nil {
		for _, env := range *input.Environments {
			if err := wire.CheckUTF8(env.PrincipalType, env.ResourceType); err != nil {
				return nil, &Error{Kind: "input", Message: err.Error()}
			}
		}
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, &Error{Kind: "input", Message: err.Error()}
	}
	if len(data) > a.maxSourceBytes {
		return nil, fmt.Errorf("analysis: input is %d bytes, above the limit of %d", len(data), a.maxSourceBytes)
	}
	return data, nil
}

func (s *CompiledSession) decodeOpen(data []byte) error {
	var result struct {
		Environments []struct {
			PrincipalType string `json:"principal_type"`
			Action        struct {
				Type *string `json:"type"`
				ID   *string `json:"id"`
			} `json:"action"`
			ResourceType string `json:"resource_type"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.Environments == nil {
		return errors.New("compiled session response has no environments")
	}
	environments := make([]RequestEnvironment, len(result.Environments))
	for i, env := range result.Environments {
		if env.PrincipalType == "" || env.Action.Type == nil || *env.Action.Type == "" || env.Action.ID == nil || env.ResourceType == "" {
			return errors.New("compiled session response has an incomplete environment")
		}
		environments[i] = RequestEnvironment{env.PrincipalType, cedar.NewEntityUID(*env.Action.Type, *env.Action.ID), env.ResourceType}
	}
	s.environments = environments
	return nil
}
