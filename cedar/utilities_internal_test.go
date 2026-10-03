package cedar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func canonicalUtilityJSON(t *testing.T, data []byte) []byte {
	t.Helper()
	if data == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestUtilityNativeFixtures(t *testing.T) {
	read := func(path string, out any) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatal(err)
		}
	}
	var inputs []map[string]json.RawMessage
	var expected []struct {
		Name   string
		Output json.RawMessage
	}
	read("../testdata/parity/utilities/input.json", &inputs)
	read("../testdata/parity/utilities/expected.json", &expected)
	if len(inputs) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	for i, input := range inputs {
		t.Run(expected[i].Name, func(t *testing.T) {
			var name string
			if err := json.Unmarshal(input["name"], &name); err != nil || name != expected[i].Name {
				t.Fatal("fixture order mismatch")
			}
			delete(input, "name")
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			result, err := rt.callOnce(context.Background(), "cgw_utilities", data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonicalUtilityJSON(t, result), canonicalUtilityJSON(t, expected[i].Output)) {
				t.Fatalf("got %s; native result %s", result, expected[i].Output)
			}
		})
	}
}

func TestUtilityPreflight(t *testing.T) {
	ctx := context.Background()
	rt := &Runtime{maxSourceBytes: DefaultMaxSourceBytes}
	bad := string([]byte{0xff})
	uid := NewEntityUID("User", bad)
	cases := []func() error{
		func() error { _, err := rt.ParseEntityUID(ctx, bad); return err },
		func() error { _, err := uid.CedarText(ctx, rt); return err },
		func() error { _, _, err := (Context{}).Get(ctx, rt, bad); return err },
		func() error { _, err := NewContext(Record{bad: Bool(true)}).Values(ctx, rt); return err },
		func() error { _, err := (Context{}).Merge(ctx, rt, NewContext(Record{"a": String(bad)})); return err },
		func() error {
			return (Context{}).Validate(ctx, rt, SchemaFromCedar(bad), NewEntityUID("Action", "view"))
		},
		func() error { return rt.ValidateScopeVariables(ctx, SchemaFromCedar(""), uid, uid, uid) },
		func() error { _, err := rt.ConfusableStrings(ctx, PoliciesFromCedar(bad)); return err },
	}
	for _, check := range cases {
		var ce *Error
		if err := check(); !errors.As(err, &ce) || ce.Kind != KindInput {
			t.Fatalf("invalid UTF-8 reached guest: %v", err)
		}
	}
	rt.maxSourceBytes = 1
	var ce *Error
	if _, err := rt.ParseEntityUID(ctx, strings.Repeat("a", 100)); !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatalf("source limit: %v", err)
	}
	if _, err := rt.LanguageVersion(ctx); !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatalf("version envelope limit: %v", err)
	}
	for _, valid := range []*bool{nil, new(bool)} {
		if err := utilityValidationResult(utilityOutput{Valid: valid}, nil); !errors.As(err, &ce) || ce.Kind != KindFault {
			t.Fatalf("accepted malformed validation result: %v", err)
		}
	}
	trueValue := true
	if err := utilityValidationResult(utilityOutput{Valid: &trueValue}, nil); err != nil {
		t.Fatal(err)
	}
	if got := moduleError(&wire.Error{Kind: "entity_uid", Message: "invalid UID"}); got.Kind != KindEntityUID {
		t.Fatal("standalone UID error became a fault")
	}
}

func TestUtilityReadbackExactIntegers(t *testing.T) {
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	ctx := ContextFromJSON([]byte(`{"large":9007199254740993,"max":9223372036854775807,"min":-9223372036854775808}`))
	values, err := ctx.Values(context.Background(), rt)
	want := EvalRecord{"large": Long(9007199254740993), "max": Long(9223372036854775807), "min": Long(-9223372036854775808)}
	if err != nil || !reflect.DeepEqual(values, want) {
		t.Fatalf("readback precision: %#v %v", values, err)
	}
	value, found, err := ctx.Get(context.Background(), rt, "large")
	if err != nil || !found || value != Long(9007199254740993) {
		t.Fatalf("lookup precision: %#v %v %v", value, found, err)
	}
	value, found, err = ctx.Get(context.Background(), rt, "missing")
	if err != nil || found || value != nil {
		t.Fatalf("missing lookup: %#v %v %v", value, found, err)
	}
	merged, err := ctx.Merge(context.Background(), rt, NewContext(Record{"other": Long(-9007199254740993)}))
	if err != nil {
		t.Fatal(err)
	}
	want["other"] = Long(-9007199254740993)
	values, err = merged.Values(context.Background(), rt)
	if err != nil || !reflect.DeepEqual(values, want) {
		t.Fatalf("merge precision: %#v %v", values, err)
	}
}

func TestUtilityContextInputProtocol(t *testing.T) {
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	for _, tc := range []struct {
		input string
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
		out, err := rt.callOnce(context.Background(), "cgw_utilities", []byte(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		var result utilityOutput
		if err := json.Unmarshal(out, &result); err != nil || result.Error == nil || result.Error.Kind != tc.kind {
			t.Fatalf("input %s: output %s, error %v; want %s", tc.input, out, err, tc.kind)
		}
	}
}

func TestUtilityWarningResponses(t *testing.T) {
	policies := PoliciesFromCedar("x")
	valid := PolicyMessage{PolicyID: "", Message: "warning", Category: "mixed_script_string", Severity: SeverityWarning}
	for _, warning := range []PolicyMessage{
		{Message: "warning", Severity: SeverityWarning},
		{Message: "warning", Category: "mixed_script_string", Severity: SeverityError},
		{Category: "mixed_script_string", Severity: SeverityWarning},
		{Message: "warning", Category: "mixed_script_string", Severity: SeverityWarning, Spans: []SourceSpan{{Offset: 1, Length: 1}}},
	} {
		warnings := []PolicyMessage{warning}
		result, err := utilityWarningsResult(utilityOutput{Warnings: &warnings}, nil, policies)
		var ce *Error
		if !errors.As(err, &ce) || ce.Kind != KindFault || result != nil {
			t.Fatalf("accepted malformed warning: %+v %v", result, err)
		}
	}
	warnings := []PolicyMessage{valid}
	result, err := utilityWarningsResult(utilityOutput{Warnings: &warnings}, nil, policies)
	if err != nil || !reflect.DeepEqual(result, warnings) {
		t.Fatalf("valid warning: %+v %v", result, err)
	}
	warnings[0].Spans = []SourceSpan{{Offset: 0, Length: 1}}
	result, err = utilityWarningsResult(utilityOutput{Warnings: &warnings}, nil, PoliciesFromJSON([]byte(`{}`)))
	var ce *Error
	if !errors.As(err, &ce) || ce.Kind != KindFault || result != nil {
		t.Fatalf("accepted JSON warning spans: %+v %v", result, err)
	}
}
