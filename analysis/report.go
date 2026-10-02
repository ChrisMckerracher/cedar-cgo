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

// Counterexample is rechecked with Cedar's concrete authorizer before being returned.
type Counterexample struct {
	// Request includes context and entities, except action entities supplied by the schema.
	Request cedar.Request
	// Text describes the request in Cedar syntax.
	Text string
	// First and Second follow the caller's policy-set argument order.
	First, Second cedar.Decision
}

type analyzeOutput struct {
	Results []struct {
		PrincipalType  string   `json:"principal_type"`
		Action         wire.UID `json:"action"`
		ResourceType   string   `json:"resource_type"`
		Holds          bool     `json:"holds"`
		Counterexample *struct {
			Request struct {
				Principal wire.UID        `json:"principal"`
				Action    wire.UID        `json:"action"`
				Resource  wire.UID        `json:"resource"`
				Context   json.RawMessage `json:"context"`
			} `json:"request"`
			Entities  json.RawMessage `json:"entities"`
			Text      string          `json:"text"`
			ADecision string          `json:"a_decision"`
			BDecision string          `json:"b_decision"`
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
	report := Report{Results: make([]Result, 0, len(output.Results))}
	for _, r := range output.Results {
		res := Result{
			PrincipalType: r.PrincipalType,
			Action:        cedar.NewEntityUID(r.Action.Type, r.Action.ID),
			ResourceType:  r.ResourceType,
			Holds:         r.Holds,
		}
		if c := r.Counterexample; c != nil {
			if r.Holds {
				return Report{}, errors.New("analysis: module returned a counterexample for a property that holds")
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
			if swap {
				first, second = db, da
			}
			res.Counterexample = &Counterexample{
				Request: cedar.Request{
					Principal: cedar.NewEntityUID(c.Request.Principal.Type, c.Request.Principal.ID),
					Action:    cedar.NewEntityUID(c.Request.Action.Type, c.Request.Action.ID),
					Resource:  cedar.NewEntityUID(c.Request.Resource.Type, c.Request.Resource.ID),
					Context:   cedar.ContextFromJSON(c.Request.Context),
					Entities:  cedar.EntitiesFromJSON(c.Entities),
				},
				Text:   c.Text,
				First:  first,
				Second: second,
			}
		} else if !r.Holds {
			return Report{}, errors.New("analysis: module returned a failed property without a counterexample")
		}
		report.Results = append(report.Results, res)
	}
	return report, nil
}
