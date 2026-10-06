package report

import (
	"encoding/json/v2"
	"testing"

	requests "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
)

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
	if result.Action.ID != "" || result.Holds || result.Counterexample == nil || result.Counterexample.First != requests.Allow || result.Counterexample.Second != requests.Deny {
		t.Fatalf("explicit field values changed: %+v", result)
	}
}
