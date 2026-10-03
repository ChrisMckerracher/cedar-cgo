package analysis

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
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
			if err != nil || report.Results[0].Counterexample.First != cedar.Deny || report.Results[0].Counterexample.Second != cedar.Allow {
				t.Fatalf("reversed implication evidence: %+v %v", report, err)
			}
		}
	}
}

func TestRejectIncompletePropertyEnvironment(t *testing.T) {
	for _, input := range []string{
		`{"results":[{"holds":true}]}`,
		`{"results":[{"action":{"type":"Action","id":"view"},"resource_type":"Document","holds":true}]}`,
		`{"results":[{"principal_type":"User","resource_type":"Document","holds":true}]}`,
		`{"results":[{"principal_type":"User","action":{"type":"Action","id":"view"},"holds":true}]}`,
		`{"results":[{"principal_type":"","action":{"type":"Action","id":"view"},"resource_type":"Document","holds":true}]}`,
	} {
		var output analyzeOutput
		if err := json.Unmarshal([]byte(input), &output); err != nil {
			t.Fatal(err)
		}
		if _, err := decodePropertyReport(output, false, "never_errors"); err == nil {
			t.Fatalf("missing environment accepted: %s", input)
		}
	}
	var output analyzeOutput
	if err := json.Unmarshal([]byte(`{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":true}]}`), &output); err != nil {
		t.Fatal(err)
	}
	if report, err := decodePropertyReport(output, false, "never_errors"); err != nil || len(report.Results) != 1 || report.Results[0].Action.ID != "" {
		t.Fatalf("empty action ID rejected: %+v %v", report, err)
	}
}

func TestRejectMissingPropertyResults(t *testing.T) {
	for _, input := range []string{`{}`, `{"results":null}`} {
		var output analyzeOutput
		if err := json.Unmarshal([]byte(input), &output); err != nil {
			t.Fatal(err)
		}
		if _, err := decodePropertyReport(output, false, "never_errors"); err == nil {
			t.Fatalf("missing results accepted: %s", input)
		}
	}
	var output analyzeOutput
	if err := json.Unmarshal([]byte(`{"results":[]}`), &output); err != nil {
		t.Fatal(err)
	}
	if report, err := decodePropertyReport(output, false, "never_errors"); err != nil || !report.Holds() {
		t.Fatalf("explicit empty results rejected: %+v %v", report, err)
	}
}

func TestPropertyReportFieldPresence(t *testing.T) {
	const counterexample = `{"request":{"principal":{"type":"User","id":"u"},"action":{"type":"Action","id":""},"resource":{"type":"Document","id":"d"},"context":{}},"entities":[],"text":"concrete request","a_decision":"allow","b_decision":"deny"}`
	for _, record := range []string{
		`{"principal_type":"User","action":{"type":"Action"},"resource_type":"Document","holds":false}`,
		`{"principal_type":"User","action":{"type":"Action","id":null},"resource_type":"Document","holds":false}`,
		`{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document"}`,
		`{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":null}`,
	} {
		var output analyzeOutput
		input := `{"results":[` + record[:len(record)-1] + `,"counterexample":` + counterexample + `}]}`
		if err := json.Unmarshal([]byte(input), &output); err != nil {
			t.Fatal(err)
		}
		if _, err := decodePropertyReport(output, false, "equivalent"); err == nil {
			t.Fatalf("missing or null property field accepted: %s", input)
		}
	}
	var output analyzeOutput
	input := `{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":false,"counterexample":` + counterexample + `}]}`
	if err := json.Unmarshal([]byte(input), &output); err != nil {
		t.Fatal(err)
	}
	report, err := decodePropertyReport(output, false, "equivalent")
	if err != nil || len(report.Results) != 1 {
		t.Fatalf("explicit empty ID and false result rejected: %+v %v", report, err)
	}
	result := report.Results[0]
	if result.Action.ID != "" || result.Holds || result.Counterexample == nil || result.Counterexample.First != cedar.Allow || result.Counterexample.Second != cedar.Deny {
		t.Fatalf("explicit field values changed: %+v", result)
	}
}

func TestPolicyEvaluationErrorFields(t *testing.T) {
	for _, errorRecord := range []string{
		`{"message":"overflow"}`,
		`{"policy_id":null,"message":"overflow"}`,
		`{"policy_id":"p"}`,
		`{"policy_id":"p","message":null}`,
		`{"policy_id":"p","message":""}`,
	} {
		var evaluation PolicyEvaluation
		if err := json.Unmarshal([]byte(`{"matched":false,"errors":[`+errorRecord+`]}`), &evaluation); err == nil {
			t.Fatalf("incomplete error accepted: %s", errorRecord)
		}
	}
	for _, id := range []string{"", "quoted\"\n\\\x00"} {
		encoded, err := json.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		var evaluation PolicyEvaluation
		if err := json.Unmarshal([]byte(`{"matched":false,"errors":[{"policy_id":`+string(encoded)+`,"message":"overflow"}]}`), &evaluation); err != nil {
			t.Fatal(err)
		}
		if len(evaluation.Errors) != 1 || evaluation.Errors[0].PolicyID != id || evaluation.Errors[0].Message != "overflow" {
			t.Fatalf("error identity changed: %+v", evaluation)
		}
	}
}

func decodeCounterexampleRecord(t *testing.T, counterexample []byte) (Report, error) {
	t.Helper()
	input := `{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":false,"counterexample":` + string(counterexample) + `}]}`
	var output analyzeOutput
	if err := json.Unmarshal([]byte(input), &output); err != nil {
		t.Fatal(err)
	}
	return decodePropertyReport(output, false, "equivalent")
}

func TestPropertyCounterexamplePayloads(t *testing.T) {
	check := func(name string, mutate func(map[string]any, map[string]any)) {
		t.Run(name, func(t *testing.T) {
			var request map[string]any
			if err := json.Unmarshal([]byte(propertyRequestJSON), &request); err != nil {
				t.Fatal(err)
			}
			counterexample := map[string]any{
				"request": request, "entities": []any{}, "a_decision": "allow", "b_decision": "deny",
			}
			mutate(counterexample, request)
			data, err := json.Marshal(counterexample)
			if err != nil {
				t.Fatal(err)
			}
			if report, err := decodeCounterexampleRecord(t, data); err == nil {
				t.Fatalf("invalid counterexample accepted: %+v", report)
			}
		})
	}
	for _, part := range []string{"principal", "action", "resource"} {
		check(part+" missing", func(_ map[string]any, request map[string]any) { delete(request, part) })
		check(part+" null", func(_ map[string]any, request map[string]any) { request[part] = nil })
		check(part+" wrong type", func(_ map[string]any, request map[string]any) {
			request[part].(map[string]any)["type"] = "Other"
		})
		for _, field := range []string{"type", "id"} {
			check(part+" "+field+" missing", func(_ map[string]any, request map[string]any) {
				delete(request[part].(map[string]any), field)
			})
			check(part+" "+field+" null", func(_ map[string]any, request map[string]any) {
				request[part].(map[string]any)[field] = nil
			})
		}
	}
	check("action wrong ID", func(_ map[string]any, request map[string]any) {
		request["action"].(map[string]any)["id"] = "other"
	})
	check("request missing", func(counterexample map[string]any, _ map[string]any) { delete(counterexample, "request") })
	check("request null", func(counterexample map[string]any, _ map[string]any) { counterexample["request"] = nil })
	check("context missing", func(_ map[string]any, request map[string]any) { delete(request, "context") })
	check("context null", func(_ map[string]any, request map[string]any) { request["context"] = nil })
	check("context array", func(_ map[string]any, request map[string]any) { request["context"] = []any{} })
	check("entities missing", func(counterexample map[string]any, _ map[string]any) { delete(counterexample, "entities") })
	check("entities null", func(counterexample map[string]any, _ map[string]any) { counterexample["entities"] = nil })
	check("entities object", func(counterexample map[string]any, _ map[string]any) { counterexample["entities"] = map[string]any{} })
	data := `{"request":` + propertyRequestJSON + `,"entities":[],"a_decision":"allow","b_decision":"deny"}`
	report, err := decodeCounterexampleRecord(t, []byte(data))
	if err != nil || len(report.Results) != 1 || report.Results[0].Counterexample == nil {
		t.Fatalf("valid empty payload rejected: %+v %v", report, err)
	}
	request := report.Results[0].Counterexample.Request
	if request.Principal.ID != "" || request.Action.ID != "" || request.Resource.ID != "" {
		t.Fatalf("empty IDs changed: %+v", request)
	}
	contextJSON, contextErr := request.Context.MarshalJSON()
	entitiesJSON, entitiesErr := request.Entities.MarshalJSON()
	if contextErr != nil || entitiesErr != nil || string(contextJSON) != "{}" || string(entitiesJSON) != "[]" {
		t.Fatalf("empty JSON changed: %s %s %v %v", contextJSON, entitiesJSON, contextErr, entitiesErr)
	}
}

func TestPropertyCounterexampleRawValues(t *testing.T) {
	const contextJSON = `{ "large": 9007199254740993, "min": -9223372036854775808, "max": 9223372036854775807, "member": {"__entity":{"type":"User","id":"雪"}}, "decimal": {"__extn":{"fn":"decimal","arg":"1.25"}}, "nested": [1, {"enabled":true}] }`
	const entitiesJSON = `[ { "uid": {"type":"User","id":""}, "attrs": {"large":9007199254740993,"min":-9223372036854775808,"max":9223372036854775807,"ip":{"__extn":{"fn":"ip","arg":"10.0.0.1"}}}, "parents": [] } ]`
	requestJSON := propertyRequestJSON[:len(propertyRequestJSON)-3] + contextJSON + `}`
	data := `{"request":` + requestJSON + `,"entities":` + entitiesJSON + `,"a_decision":"allow","b_decision":"deny"}`
	report, err := decodeCounterexampleRecord(t, []byte(data))
	if err != nil || len(report.Results) != 1 || report.Results[0].Counterexample == nil {
		t.Fatalf("native typed payload rejected: %+v %v", report, err)
	}
	request := report.Results[0].Counterexample.Request
	contextOut, contextErr := request.Context.MarshalJSON()
	entitiesOut, entitiesErr := request.Entities.MarshalJSON()
	if contextErr != nil || entitiesErr != nil || !bytes.Equal(contextOut, []byte(contextJSON)) || !bytes.Equal(entitiesOut, []byte(entitiesJSON)) {
		t.Fatalf("raw typed JSON changed: %s %s %v %v", contextOut, entitiesOut, contextErr, entitiesErr)
	}
}

func TestPropertyCounterexampleEntityRecords(t *testing.T) {
	for _, entity := range []string{
		`null`, `[]`, `true`, `"entity"`, `{}`,
		`{"uid":null,"attrs":{},"parents":[]}`,
		`{"uid":{"type":"User"},"attrs":{},"parents":[]}`,
		`{"uid":{"type":"User","id":null},"attrs":{},"parents":[]}`,
		`{"uid":{"id":""},"attrs":{},"parents":[]}`,
		`{"uid":{"type":null,"id":""},"attrs":{},"parents":[]}`,
		`{"uid":{"type":"","id":""},"attrs":{},"parents":[]}`,
		`{"uid":{"__entity":{"type":"User","id":""}},"attrs":{},"parents":[]}`,
		`{"uid":{"type":"User","id":""},"parents":[]}`,
		`{"uid":{"type":"User","id":""},"attrs":null,"parents":[]}`,
		`{"uid":{"type":"User","id":""},"attrs":[],"parents":[]}`,
		`{"uid":{"type":"User","id":""},"attrs":{}}`,
		`{"uid":{"type":"User","id":""},"attrs":{},"parents":null}`,
		`{"uid":{"type":"User","id":""},"attrs":{},"parents":{}}`,
		`{"uid":{"type":"User","id":""},"attrs":{},"parents":[null]}`,
		`{"uid":{"type":"User","id":""},"attrs":{},"parents":[{"type":"Group"}]}`,
		`{"uid":{"type":"User","id":""},"attrs":{},"parents":[{"id":""}]}`,
		`{"uid":{"type":"User","id":""},"attrs":{},"parents":[],"tags":null}`,
		`{"uid":{"type":"User","id":""},"attrs":{},"parents":[],"tags":[]}`,
	} {
		data := `{"request":` + propertyRequestJSON + `,"entities":[` + entity + `],"a_decision":"allow","b_decision":"deny"}`
		if report, err := decodeCounterexampleRecord(t, []byte(data)); err == nil {
			t.Fatalf("invalid native entity record accepted: %s; report %+v", entity, report)
		}
	}
	const entityJSON = `[ {"uid":{"type":"User","id":""},"attrs":{"large":9007199254740993,"extension":{"__extn":{"fn":"decimal","arg":"1.25"}}},"parents":[{"type":"NS::Group","id":"雪"}],"tags":{"label":"😀"}}, {"uid":{"type":"NS::Group","id":"雪"},"attrs":{},"parents":[]} ]`
	data := `{"request":` + propertyRequestJSON + `,"entities":` + entityJSON + `,"a_decision":"allow","b_decision":"deny"}`
	report, err := decodeCounterexampleRecord(t, []byte(data))
	if err != nil || len(report.Results) != 1 || report.Results[0].Counterexample == nil {
		t.Fatalf("valid native entity boundary rejected: %+v %v", report, err)
	}
	got, err := report.Results[0].Counterexample.Request.Entities.MarshalJSON()
	if err != nil || !bytes.Equal(got, []byte(entityJSON)) {
		t.Fatalf("raw native entity values changed: %s %v", got, err)
	}
}
