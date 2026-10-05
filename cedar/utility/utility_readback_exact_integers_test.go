package utility

import (
	context "context"
	json "encoding/json"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	reflect "reflect"
	testing "testing"
)

func TestUtilityReadbackExactIntegers(t *testing.T) {
	rt, err := newRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(context.Background())
	ctx := cedarrequest.ContextFromJSON([]byte(`{"large":9007199254740993,"max":9223372036854775807,"min":-9223372036854775808}`))
	values, err := ctx.Values(context.Background(), rt)
	want := cedarvalue.EvalRecord{"large": cedarvalue.Long(9007199254740993), "max": cedarvalue.Long(9223372036854775807), "min": cedarvalue.Long(-9223372036854775808)}
	if err != nil || !reflect.DeepEqual(values, want) {
		t.Fatalf("readback precision: %#v %v", values, err)
	}
	value, found, err := ctx.Get(context.Background(), rt, "large")
	if err != nil || !found || value != cedarvalue.Long(9007199254740993) {
		t.Fatalf("lookup precision: %#v %v %v", value, found, err)
	}
	value, found, err = ctx.Get(context.Background(), rt, "missing")
	if err != nil || found || value != nil {
		t.Fatalf("missing lookup: %#v %v %v", value, found, err)
	}
	merged, err := ctx.Merge(context.Background(), rt, cedarrequest.NewContext(cedarvalue.Record{"other": cedarvalue.Long(-9007199254740993)}))
	if err != nil {
		t.Fatal(err)
	}
	want["other"] = cedarvalue.Long(-9007199254740993)
	values, err = merged.Values(context.Background(), rt)
	if err != nil || !reflect.DeepEqual(values, want) {
		t.Fatalf("merge precision: %#v %v", values, err)
	}
}

func TestUtilityContextInputProtocol(t *testing.T) {
	rt, err := newRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(context.Background())
	for _, tc := range []struct {
		Input string
		kind  string
	}{
		{`{"operation":"context_values"}`, "input"},
		{`{"operation":"context_get","context":{}}`, "input"},
		{`{"operation":"context_merge","context":{}}`, "input"},
		{`{"operation":"context_validate","context":{},"action":{"type":"Action","id":"view"}}`, "input"},
		{`{"operation":"context_values","context":{},"unexpected":true}`, "input"},
		{`{"operation":"context_values","context":null}`, "context"},
		{`{"operation":"context_get","context":null,"key":"x"}`, "context"},
		{`{"operation":"context_merge","context":{},"other":null}`, "context"},
		{`{"operation":"context_validate","context":null,"schema":{"format":"cedar","text":""},"action":{"type":"Action","id":"view"}}`, "context"},
	} {
		out, err := rt.runtime.CallOnce(context.Background(), "cgw_utilities", []byte(tc.Input))
		if err != nil {
			t.Fatal(err)
		}
		var result execution.UtilityOutput
		if err := json.Unmarshal(out, &result); err != nil || result.Error == nil || result.Error.Kind != tc.kind {
			t.Fatalf("input %s: output %s, error %v; want %s", tc.Input, out, err, tc.kind)
		}
	}
}

func TestUtilityWarningResponses(t *testing.T) {
	policies := cedarpolicy.PoliciesFromCedar("x")
	valid := diagnostic.PolicyMessage{PolicyID: "", Message: "warning", Category: "mixed_script_string", Severity: diagnostic.SeverityWarning}
	for _, warning := range []diagnostic.PolicyMessage{
		{Message: "warning", Severity: diagnostic.SeverityWarning},
		{Message: "warning", Category: "mixed_script_string", Severity: diagnostic.SeverityError},
		{Category: "mixed_script_string", Severity: diagnostic.SeverityWarning},
		{Message: "warning", Category: "mixed_script_string", Severity: diagnostic.SeverityWarning, Spans: []diagnostic.SourceSpan{{Offset: 1, Length: 1}}},
	} {
		warnings := []diagnostic.PolicyMessage{warning}
		result, err := UtilityWarningsResult(execution.UtilityOutput{Warnings: &warnings}, nil, policies)
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault || result != nil {
			t.Fatalf("accepted malformed warning: %+v %v", result, err)
		}
	}
	warnings := []diagnostic.PolicyMessage{valid}
	result, err := UtilityWarningsResult(execution.UtilityOutput{Warnings: &warnings}, nil, policies)
	if err != nil || !reflect.DeepEqual(result, warnings) {
		t.Fatalf("valid warning: %+v %v", result, err)
	}
	warnings[0].Spans = []diagnostic.SourceSpan{{Offset: 0, Length: 1}}
	result, err = UtilityWarningsResult(execution.UtilityOutput{Warnings: &warnings}, nil, cedarpolicy.PoliciesFromJSON([]byte(`{}`)))
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault || result != nil {
		t.Fatalf("accepted JSON warning spans: %+v %v", result, err)
	}
}
