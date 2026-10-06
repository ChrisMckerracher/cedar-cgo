package compiled

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	uids "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
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
	Environments *[]compiledEnvironment `json:"environments,omitzero"`
	Policies     *wire.Source           `json:"policies,omitempty"`
	First        uint64                 `json:"first,omitzero"`
	Second       uint64                 `json:"second,omitzero"`
	Handle       uint64                 `json:"handle,omitzero"`
	Query        string                 `json:"query,omitempty"`
}

func (s *Session) encodeCompiled(input compiledInput) ([]byte, error) {
	data, err := json.Marshal(input, jsontext.EscapeForHTML(true), jsontext.EscapeForJS(true))
	if err != nil {
		return nil, &report.Error{Kind: "input", Message: err.Error()}
	}
	if len(data) > s.config.MaxSourceBytes {
		return nil, fmt.Errorf("analysis: input is %d bytes, above the limit of %d", len(data), s.config.MaxSourceBytes)
	}
	return data, nil
}

func (s *Session) decodeOpen(data []byte) error {
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
		environments[i] = RequestEnvironment{env.PrincipalType, uids.NewEntityUID(*env.Action.Type, *env.Action.ID), env.ResourceType}
	}
	s.environments = environments
	return nil
}
