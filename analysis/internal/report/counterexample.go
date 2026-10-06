package report

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"

	records "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	requests "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entities "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	uids "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
)

func decodeCounterexample(c *counterexampleOutput, res records.Result, query string, swap bool) (*records.Counterexample, error) {
	if res.Holds {
		return nil, errors.New("analysis: module returned a counterexample for a property that holds")
	}
	if !c.Request.Principal.matchesType(res.PrincipalType) ||
		!c.Request.Action.matchesType(res.Action.Type) || *c.Request.Action.ID != res.Action.ID ||
		!c.Request.Resource.matchesType(res.ResourceType) {
		return nil, errors.New("analysis: counterexample request does not match its environment")
	}
	var contextRecord map[string]jsontext.Value
	if err := json.Unmarshal(c.Request.Context, &contextRecord); err != nil || contextRecord == nil {
		return nil, errors.New("analysis: counterexample context is not a JSON object")
	}
	var entityArray []jsontext.Value
	if err := json.Unmarshal(c.Entities, &entityArray); err != nil || entityArray == nil {
		return nil, errors.New("analysis: counterexample entities are not a JSON array")
	}
	for _, entity := range entityArray {
		if err := validateCounterexampleEntity(entity); err != nil {
			return nil, err
		}
	}
	da, err := decision(c.ADecision)
	if err != nil {
		return nil, err
	}
	db, err := decision(c.BDecision)
	if err != nil {
		return nil, err
	}
	first, second := da, db
	firstEval, secondEval := c.AEvaluation, c.BEvaluation
	if err := validateEvidence(query, da, db, firstEval, secondEval); err != nil {
		return nil, err
	}
	if swap {
		first, second = db, da
		firstEval, secondEval = secondEval, firstEval
	}
	res.Counterexample = &records.Counterexample{
		Request: requests.Request{
			Principal: uids.NewEntityUID(*c.Request.Principal.Type, *c.Request.Principal.ID),
			Action:    uids.NewEntityUID(*c.Request.Action.Type, *c.Request.Action.ID),
			Resource:  uids.NewEntityUID(*c.Request.Resource.Type, *c.Request.Resource.ID),
			Context:   requests.ContextFromJSON(c.Request.Context),
			Entities:  entities.EntitiesFromJSON(c.Entities),
		},
		Text:            c.Text,
		First:           first,
		Second:          second,
		FirstEvaluation: firstEval, SecondEvaluation: secondEval,
	}
	return res.Counterexample, nil
}
