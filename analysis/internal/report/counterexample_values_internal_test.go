package report

import (
	"bytes"
	"testing"
)

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
