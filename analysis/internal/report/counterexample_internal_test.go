package report

import (
	"encoding/json"
	"testing"
)

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
