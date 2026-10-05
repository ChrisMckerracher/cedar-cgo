package report

import (
	"encoding/json"
	"errors"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type counterexampleUID struct {
	Type *string `json:"type"`
	ID   *string `json:"id"`
}

func (u counterexampleUID) matchesType(expected string) bool {
	return u.complete() && *u.Type == expected
}

func (u counterexampleUID) complete() bool {
	return u.Type != nil && *u.Type != "" && u.ID != nil
}

func validateCounterexampleEntity(data json.RawMessage) error {
	var entity struct {
		UID     counterexampleUID          `json:"uid"`
		Attrs   map[string]json.RawMessage `json:"attrs"`
		Parents []counterexampleUID        `json:"parents"`
		Tags    json.RawMessage            `json:"tags"`
	}
	if err := json.Unmarshal(data, &entity); err != nil || !entity.UID.complete() || entity.Attrs == nil || entity.Parents == nil {
		return errors.New("analysis: counterexample entity has an invalid record or UID")
	}
	for _, parent := range entity.Parents {
		if !parent.complete() {
			return errors.New("analysis: counterexample entity has an incomplete parent UID")
		}
	}
	if len(entity.Tags) != 0 {
		var tags map[string]json.RawMessage
		if err := json.Unmarshal(entity.Tags, &tags); err != nil || tags == nil {
			return errors.New("analysis: counterexample entity tags are not a JSON object")
		}
	}
	return nil
}

type analyzeOutput struct {
	Results []environmentOutput `json:"results"`
	Error   *wire.Error         `json:"error"`
}

type environmentOutput struct {
	PrincipalType string `json:"principal_type"`
	Action        struct {
		Type string  `json:"type"`
		ID   *string `json:"id"`
	} `json:"action"`
	ResourceType   string                `json:"resource_type"`
	Holds          *bool                 `json:"holds"`
	Counterexample *counterexampleOutput `json:"counterexample"`
}

type counterexampleOutput struct {
	Request struct {
		Principal counterexampleUID `json:"principal"`
		Action    counterexampleUID `json:"action"`
		Resource  counterexampleUID `json:"resource"`
		Context   json.RawMessage   `json:"context"`
	} `json:"request"`
	Entities    json.RawMessage   `json:"entities"`
	Text        string            `json:"text"`
	ADecision   string            `json:"a_decision"`
	BDecision   string            `json:"b_decision"`
	AEvaluation *PolicyEvaluation `json:"a_evaluation"`
	BEvaluation *PolicyEvaluation `json:"b_evaluation"`
}
