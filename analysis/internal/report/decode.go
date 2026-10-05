package report

import (
	"encoding/json"
	"errors"
	"fmt"

	requests "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	uids "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
)

func decision(s string) (requests.Decision, error) {
	switch s {
	case "allow":
		return requests.Allow, nil
	case "deny":
		return requests.Deny, nil
	}
	return requests.Deny, fmt.Errorf("analysis: module returned decision %q", s)
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
			Action:        uids.NewEntityUID(r.Action.Type, *r.Action.ID),
			ResourceType:  r.ResourceType,
			Holds:         *r.Holds,
		}
		if c := r.Counterexample; c != nil {
			var err error
			res.Counterexample, err = decodeCounterexample(c, res, query, swap)
			if err != nil {
				return Report{}, err
			}
		} else if !res.Holds {
			return Report{}, errors.New("analysis: module returned a failed property without a counterexample")
		}
		report.Results = append(report.Results, res)
	}
	return report, nil
}

// Decode checks request environments and concrete counterexample records.
func Decode(data []byte, swap bool, query string) (Report, error) {
	var output analyzeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return Report{}, err
	}
	return decodePropertyReport(output, swap, query)
}
