package analysis

import (
	"encoding/json"
	"errors"
	"fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Report holds one [Result] per request environment of the schema.
type Report struct {
	Results []Result
}

// Holds reports whether the property holds for every request environment.
func (r Report) Holds() bool {
	for _, res := range r.Results {
		if !res.Holds {
			return false
		}
	}
	return true
}

// Result covers one schema-defined combination of principal type, action and resource type.
type Result struct {
	PrincipalType string
	Action        cedar.EntityUID
	ResourceType  string
	// Holds relies on SymCC's encoding and the solver's unsat answer.
	Holds bool
	// Counterexample is set when Holds is false.
	Counterexample *Counterexample
}

// PolicyEvaluation records native singleton-policy matching and evaluation errors.
type PolicyEvaluation struct {
	Matched bool                  `json:"matched"`
	Errors  []cedar.PolicyMessage `json:"errors"`
}

func (p *PolicyEvaluation) UnmarshalJSON(data []byte) error {
	var result struct {
		Matched *bool `json:"matched"`
		Errors  []struct {
			PolicyID *string `json:"policy_id"`
			Message  *string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.Matched == nil || result.Errors == nil {
		return errors.New("analysis: incomplete policy evaluation")
	}
	errorsOut := make([]cedar.PolicyMessage, len(result.Errors))
	for i, entry := range result.Errors {
		if entry.PolicyID == nil || entry.Message == nil || *entry.Message == "" {
			return errors.New("analysis: incomplete evaluation error")
		}
		errorsOut[i] = cedar.PolicyMessage{PolicyID: *entry.PolicyID, Message: *entry.Message}
	}
	p.Matched, p.Errors = *result.Matched, errorsOut
	return nil
}

// Counterexample is rechecked with Cedar's concrete authorizer before being returned.
type Counterexample struct {
	// Request includes context and entities, except action entities supplied by the schema.
	Request cedar.Request
	// Text describes the request in Cedar syntax.
	Text string
	// First and Second follow the caller's policy-set argument order.
	First, Second cedar.Decision
	// Evaluations are present only for matching and error queries.
	FirstEvaluation, SecondEvaluation *PolicyEvaluation
}

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
	Results []struct {
		PrincipalType string `json:"principal_type"`
		Action        struct {
			Type string  `json:"type"`
			ID   *string `json:"id"`
		} `json:"action"`
		ResourceType   string `json:"resource_type"`
		Holds          *bool  `json:"holds"`
		Counterexample *struct {
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
		} `json:"counterexample"`
	} `json:"results"`
	Error *wire.Error `json:"error"`
}

func decision(s string) (cedar.Decision, error) {
	switch s {
	case "allow":
		return cedar.Allow, nil
	case "deny":
		return cedar.Deny, nil
	}
	return cedar.Deny, fmt.Errorf("analysis: module returned decision %q", s)
}

func decodeReport(output analyzeOutput, swap bool) (Report, error) {
	return decodePropertyReport(output, swap, "")
}

func decodePropertyReport(output analyzeOutput, swap bool, query string) (Report, error) {
	if output.Results == nil {
		return Report{}, errors.New("analysis: module returned no results")
	}
	report := Report{Results: make([]Result, 0, len(output.Results))}
	for _, r := range output.Results {
		if r.PrincipalType == "" || r.Action.Type == "" || r.Action.ID == nil || r.ResourceType == "" {
			return Report{}, errors.New("analysis: module returned an incomplete request environment")
		}
		if r.Holds == nil {
			return Report{}, errors.New("analysis: module returned no property result flag")
		}
		res := Result{
			PrincipalType: r.PrincipalType,
			Action:        cedar.NewEntityUID(r.Action.Type, *r.Action.ID),
			ResourceType:  r.ResourceType,
			Holds:         *r.Holds,
		}
		if c := r.Counterexample; c != nil {
			if res.Holds {
				return Report{}, errors.New("analysis: module returned a counterexample for a property that holds")
			}
			if !c.Request.Principal.matchesType(res.PrincipalType) ||
				!c.Request.Action.matchesType(res.Action.Type) || *c.Request.Action.ID != res.Action.ID ||
				!c.Request.Resource.matchesType(res.ResourceType) {
				return Report{}, errors.New("analysis: counterexample request does not match its environment")
			}
			var contextRecord map[string]json.RawMessage
			if err := json.Unmarshal(c.Request.Context, &contextRecord); err != nil || contextRecord == nil {
				return Report{}, errors.New("analysis: counterexample context is not a JSON object")
			}
			var entityArray []json.RawMessage
			if err := json.Unmarshal(c.Entities, &entityArray); err != nil || entityArray == nil {
				return Report{}, errors.New("analysis: counterexample entities are not a JSON array")
			}
			for _, entity := range entityArray {
				if err := validateCounterexampleEntity(entity); err != nil {
					return Report{}, err
				}
			}
			da, err := decision(c.ADecision)
			if err != nil {
				return Report{}, err
			}
			db, err := decision(c.BDecision)
			if err != nil {
				return Report{}, err
			}
			first, second := da, db
			firstEval, secondEval := c.AEvaluation, c.BEvaluation
			unary := query == "never_errors" || query == "always_matches" || query == "never_matches"
			matching := unary || query == "matches_equivalent" || query == "matches_implies" || query == "matches_disjoint"
			if matching && (firstEval == nil || (!unary && secondEval == nil)) {
				return Report{}, errors.New("analysis: module returned no policy evaluation for a matching or error query")
			}
			if unary && (db != cedar.Deny || secondEval != nil) {
				return Report{}, errors.New("analysis: module returned an invalid result for the unused policy set")
			}
			for i, evaluation := range []*PolicyEvaluation{firstEval, secondEval} {
				if evaluation == nil {
					continue
				}
				if evaluation.Errors == nil || (evaluation.Matched && len(evaluation.Errors) != 0) {
					return Report{}, errors.New("analysis: module returned an invalid policy evaluation")
				}
				if matching && len(evaluation.Errors) > 1 {
					return Report{}, errors.New("analysis: module returned multiple errors for one policy")
				}
				if matching && !evaluation.Matched && [2]cedar.Decision{da, db}[i] != cedar.Deny {
					return Report{}, errors.New("analysis: module returned allow for a policy that does not match")
				}
			}
			genuine := true
			switch query {
			case "equivalent":
				genuine = da != db
			case "implies":
				genuine = da == cedar.Allow && db == cedar.Deny
			case "never_errors":
				genuine = len(firstEval.Errors) != 0
			case "always_matches":
				genuine = !firstEval.Matched
			case "never_matches":
				genuine = firstEval.Matched
			case "matches_equivalent":
				genuine = firstEval.Matched != secondEval.Matched
			case "matches_implies":
				genuine = firstEval.Matched && !secondEval.Matched
			case "matches_disjoint":
				genuine = firstEval.Matched && secondEval.Matched
			case "disjoint":
				genuine = da == cedar.Allow && db == cedar.Allow
			}
			if !genuine {
				return Report{}, errors.New("analysis: module returned a counterexample that does not violate the property")
			}
			if swap {
				first, second = db, da
				firstEval, secondEval = secondEval, firstEval
			}
			res.Counterexample = &Counterexample{
				Request: cedar.Request{
					Principal: cedar.NewEntityUID(*c.Request.Principal.Type, *c.Request.Principal.ID),
					Action:    cedar.NewEntityUID(*c.Request.Action.Type, *c.Request.Action.ID),
					Resource:  cedar.NewEntityUID(*c.Request.Resource.Type, *c.Request.Resource.ID),
					Context:   cedar.ContextFromJSON(c.Request.Context),
					Entities:  cedar.EntitiesFromJSON(c.Entities),
				},
				Text:            c.Text,
				First:           first,
				Second:          second,
				FirstEvaluation: firstEval, SecondEvaluation: secondEval,
			}
		} else if !res.Holds {
			return Report{}, errors.New("analysis: module returned a failed property without a counterexample")
		}
		report.Results = append(report.Results, res)
	}
	return report, nil
}
