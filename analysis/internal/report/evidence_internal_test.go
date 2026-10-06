package report

import (
	"encoding/json/v2"
	"strings"
	"testing"

	requests "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
)

const propertyRequestJSON = `{"principal":{"type":"User","id":""},"action":{"type":"Action","id":""},"resource":{"type":"Document","id":""},"context":{}}`

func TestSingletonEvaluationDecisionConsistency(t *testing.T) {
	const matched = `{"matched":true,"errors":[]}`
	const unmatched = `{"matched":false,"errors":[]}`
	const failed = `{"matched":false,"errors":[{"policy_id":"","message":"overflow"}]}`
	const twoErrors = `{"matched":false,"errors":[{"policy_id":"p","message":"overflow"},{"policy_id":"q","message":"overflow"}]}`
	for _, tc := range []struct {
		name, query, first, second, firstEval, secondEval, wantError string
	}{
		{"first nonmatch allows", "always_matches", "allow", "deny", unmatched, `null`, "allow for a policy that does not match"},
		{"first error allows", "never_errors", "allow", "deny", failed, `null`, "allow for a policy that does not match"},
		{"pairwise first nonmatch allows", "matches_equivalent", "allow", "deny", unmatched, matched, "allow for a policy that does not match"},
		{"pairwise second nonmatch allows", "matches_equivalent", "allow", "allow", matched, unmatched, "allow for a policy that does not match"},
		{"pairwise second error allows", "matches_implies", "deny", "allow", matched, failed, "allow for a policy that does not match"},
		{"first has two errors", "never_errors", "deny", "deny", twoErrors, `null`, "multiple errors for one policy"},
		{"second has two errors", "matches_equivalent", "allow", "deny", matched, twoErrors, "multiple errors for one policy"},
		{"unary second allows", "never_matches", "allow", "allow", matched, `null`, "unused policy set"},
		{"unary second has evaluation", "never_matches", "deny", "deny", matched, unmatched, "unused policy set"},
		{"nonmatch denies", "always_matches", "deny", "deny", unmatched, `null`, ""},
		{"one error denies", "never_errors", "deny", "deny", failed, `null`, ""},
		{"permit matches and allows", "never_matches", "allow", "deny", matched, `null`, ""},
		{"forbid matches and denies", "never_matches", "deny", "deny", matched, `null`, ""},
		{"both forbids match and deny", "matches_disjoint", "deny", "deny", matched, matched, ""},
		{"forbid match implies permit nonmatch", "matches_implies", "deny", "deny", matched, unmatched, ""},
		{"permit nonmatch differs from forbid match", "matches_equivalent", "deny", "deny", unmatched, matched, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":false,"counterexample":{"request":` + propertyRequestJSON + `,"entities":[],"a_decision":"` + tc.first + `","b_decision":"` + tc.second + `","a_evaluation":` + tc.firstEval + `,"b_evaluation":` + tc.secondEval + `}}]}`
			var output analyzeOutput
			if err := json.Unmarshal([]byte(input), &output); err != nil {
				t.Fatal(err)
			}
			report, err := decodePropertyReport(output, false, tc.query)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("wrong guard: report %+v, error %v; want %s", report, err, tc.wantError)
				}
				return
			}
			if err != nil || len(report.Results) != 1 || report.Results[0].Counterexample == nil {
				t.Fatalf("valid native singleton evidence rejected: %+v %v", report, err)
			}
			cex := report.Results[0].Counterexample
			if cex.First.String() != tc.first || cex.Second.String() != tc.second {
				t.Fatalf("native decisions changed: %+v", cex)
			}
		})
	}
}

func TestRejectInvalidPropertyEvidence(t *testing.T) {
	for _, test := range []struct {
		query    string
		evidence string
	}{
		{"never_errors", `null`},
		{"never_errors", `{"matched":false,"errors":[]}`},
		{"never_matches", `{"matched":false,"errors":[]}`},
		{"always_matches", `{"matched":true,"errors":[]}`},
		{"never_matches", `{"matched":true,"errors":[{"policy_id":"p","message":"error"}]}`},
		{"matches_equivalent", `{"matched":true,"errors":[]}`},
	} {
		var output analyzeOutput
		input := `{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":false,"counterexample":{"request":` + propertyRequestJSON + `,"entities":[],"a_decision":"deny","b_decision":"deny","a_evaluation":` + test.evidence + `}}]}`
		if err := json.Unmarshal([]byte(input), &output); err != nil {
			t.Fatal(err)
		}
		if _, err := decodePropertyReport(output, false, test.query); err == nil {
			t.Fatalf("invalid %s evidence accepted %s", test.query, test.evidence)
		}
	}
}

func TestRejectContradictoryDecisionEvidence(t *testing.T) {
	for _, test := range []struct {
		query, first, second string
		valid                bool
	}{
		{"equivalent", "allow", "allow", false},
		{"equivalent", "deny", "deny", false},
		{"equivalent", "allow", "deny", true},
		{"equivalent", "deny", "allow", true},
		{"implies", "allow", "allow", false},
		{"implies", "deny", "allow", false},
		{"implies", "deny", "deny", false},
		{"implies", "allow", "deny", true},
	} {
		var output analyzeOutput
		input := `{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":false,"counterexample":{"request":` + propertyRequestJSON + `,"entities":[],"a_decision":"` + test.first + `","b_decision":"` + test.second + `"}}]}`
		if err := json.Unmarshal([]byte(input), &output); err != nil {
			t.Fatal(err)
		}
		_, err := decodePropertyReport(output, false, test.query)
		if (err == nil) != test.valid {
			t.Fatalf("query %s: decisions %s/%s, error %v", test.query, test.first, test.second, err)
		}
		if test.valid && test.query == "implies" {
			report, err := decodePropertyReport(output, true, test.query)
			if err != nil || report.Results[0].Counterexample.First != requests.Deny || report.Results[0].Counterexample.Second != requests.Allow {
				t.Fatalf("reversed implication evidence: %+v %v", report, err)
			}
		}
	}
}
