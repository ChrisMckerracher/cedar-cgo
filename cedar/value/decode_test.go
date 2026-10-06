package value

import "testing"

func TestStrictEvaluationJSON(t *testing.T) {
	for _, input := range []string{
		`{"string":"\ud800"}`,
		`{"long":1,"long":2}`,
		`{"record":{"n":{"long":1},"n":{"long":2}}}`,
		`{"entity_uid":{"type":"User","id":"\ud800"}}`,
		`{"long":9007199254740993} {}`,
	} {
		if result, err := DecodeEvalResult([]byte(input)); err == nil || result != nil {
			t.Fatalf("malformed evaluation JSON accepted: %s; %v %v", input, result, err)
		}
	}
	result, err := DecodeEvalResult([]byte(`{"record":{"n":{"long":9007199254740993}}}`))
	if err != nil || result.(EvalRecord)["n"] != Long(9007199254740993) {
		t.Fatalf("exact integer changed: %v, %v", result, err)
	}
}
