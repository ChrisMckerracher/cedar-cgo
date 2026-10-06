package report

import (
	"errors"

	records "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	requests "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
)

func validateEvidence(query string, da, db requests.Decision, firstEval, secondEval *records.PolicyEvaluation) error {
	unary := query == "never_errors" || query == "always_matches" || query == "never_matches"
	matching := unary || query == "matches_equivalent" || query == "matches_implies" || query == "matches_disjoint"
	if matching && (firstEval == nil || (!unary && secondEval == nil)) {
		return errors.New("analysis: module returned no policy evaluation for a matching or error query")
	}
	if unary && (db != requests.Deny || secondEval != nil) {
		return errors.New("analysis: module returned an invalid result for the unused policy set")
	}
	for i, evaluation := range []*records.PolicyEvaluation{firstEval, secondEval} {
		if evaluation == nil {
			continue
		}
		if evaluation.Errors == nil || (evaluation.Matched && len(evaluation.Errors) != 0) {
			return errors.New("analysis: module returned an invalid policy evaluation")
		}
		if matching && len(evaluation.Errors) > 1 {
			return errors.New("analysis: module returned multiple errors for one policy")
		}
		if matching && !evaluation.Matched && [2]requests.Decision{da, db}[i] != requests.Deny {
			return errors.New("analysis: module returned allow for a policy that does not match")
		}
	}
	genuine := true
	switch query {
	case "equivalent":
		genuine = da != db
	case "implies":
		genuine = da == requests.Allow && db == requests.Deny
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
		genuine = da == requests.Allow && db == requests.Allow
	}
	if !genuine {
		return errors.New("analysis: module returned a counterexample that does not violate the property")
	}
	return nil
}
