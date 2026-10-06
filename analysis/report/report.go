package report

import (
	"encoding/json/v2"
	"errors"

	requests "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	uids "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
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
	Action        uids.EntityUID
	ResourceType  string
	// Holds relies on SymCC's encoding and the solver's unsat answer.
	Holds bool
	// Counterexample is set when Holds is false.
	Counterexample *Counterexample
}

// PolicyEvaluation records native singleton-policy matching and evaluation errors.
type PolicyEvaluation struct {
	Matched bool                       `json:"matched"`
	Errors  []diagnostic.PolicyMessage `json:"errors"`
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
	errorsOut := make([]diagnostic.PolicyMessage, len(result.Errors))
	for i, entry := range result.Errors {
		if entry.PolicyID == nil || entry.Message == nil || *entry.Message == "" {
			return errors.New("analysis: incomplete evaluation error")
		}
		errorsOut[i] = diagnostic.PolicyMessage{PolicyID: *entry.PolicyID, Message: *entry.Message}
	}
	p.Matched, p.Errors = *result.Matched, errorsOut
	return nil
}

// Counterexample is rechecked with Cedar's concrete authorizer before being returned.
type Counterexample struct {
	// Request includes context and entities, except action entities supplied by the schema.
	Request requests.Request
	// Text describes the request in Cedar syntax.
	Text string
	// First and Second follow the caller's policy-set argument order.
	First, Second requests.Decision
	// Evaluations are present only for matching and error queries.
	FirstEvaluation, SecondEvaluation *PolicyEvaluation
}
