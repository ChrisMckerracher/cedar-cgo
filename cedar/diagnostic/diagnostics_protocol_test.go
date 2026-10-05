package diagnostic_test

import (
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"

	json "encoding/json"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	validation "github.com/ChrisMckerracher/cedar-go-wasm/cedar/validation"
	testing "testing"
)

func TestDiagnosticProtocol(t *testing.T) {
	valid := `{"passed":false,"errors":[{"policy_id":"x","message":"type mismatch","category":"unexpected_type","severity":"error","spans":[{"offset":1,"length":2}]}],"warnings":[],"schema_warnings":[]}`
	result, err := validation.DecodeValidation([]byte(valid), 10, 10)
	if err != nil || len(result.Errors) != 1 || result.Errors[0].Spans[0].Offset != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	for _, raw := range []string{
		`{}`, `null`, `{"passed":true}`, `{"passed":true,"errors":null,"warnings":[],"schema_warnings":[]}`,
		`{"passed":false,"errors":[],"warnings":[],"schema_warnings":[]}`,
		`{"passed":true,"errors":[],"warnings":[{"category":"unexpected_type","severity":"error"}],"schema_warnings":[]}`,
		`{"passed":true,"errors":[],"warnings":[{"severity":"warning"}],"schema_warnings":[]}`,
		`{"passed":true,"errors":[],"warnings":[{"message":"warning","category":"x","severity":"warning","spans":[{"offset":11,"length":0}]}],"schema_warnings":[]}`,
		`{"passed":true,"errors":[],"warnings":[{"message":"warning","category":"x","severity":"warning","spans":[{"offset":0}]}],"schema_warnings":[]}`,
		`{"passed":true,"errors":[],"warnings":[{"message":"warning","category":"x","severity":"warning","spans":[{"offset":-1,"length":1}]}],"schema_warnings":[]}`,
		`{"passed":true,"errors":[],"warnings":[{"message":"warning","category":"x","severity":"warning","spans":[{"offset":18446744073709551615,"length":1}]}],"schema_warnings":[]}`,
		valid + `{}`, string([]byte{0xff}),
	} {
		if _, err := validation.DecodeValidation([]byte(raw), 10, 10); err == nil {
			t.Errorf("accepted malformed diagnostics %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"warnings":null}`, `{"warnings":[{"category":"x","severity":"error"}]}`, `{"warnings":[{"message":"warning","category":"x","severity":"warning","spans":[{}]}]}`, `{"warnings":[]} {}`} {
		if _, err := cedarschema.DecodeSchemaWarnings([]byte(raw), 10); err == nil {
			t.Errorf("accepted malformed schema warnings %s", raw)
		}
	}
}

func FuzzDiagnostics(f *testing.F) {
	f.Add([]byte(`{"passed":true,"errors":[],"warnings":[],"schema_warnings":[]}`))
	f.Add([]byte(`{"warnings":[{"category":"shadows_builtin","severity":"warning","message":"shadow","spans":[{"offset":0,"length":1}]}]}`))
	f.Add([]byte(`{"passed":false,"errors":[{"message":"type mismatch","category":"unexpected_type","severity":"error","spans":[{"offset":18446744073709551615,"length":1}]}],"warnings":[],"schema_warnings":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}
		if result, err := validation.DecodeValidation(raw, 4096, 4096); err == nil {
			if result.Passed != (len(result.Errors) == 0) {
				t.Fatal("inconsistent status")
			}
			for _, entry := range result.Errors {
				if entry.Category == "" || entry.Severity != diagnostic.SeverityError {
					t.Fatal("invalid error metadata")
				}
			}
			if _, err := json.Marshal(result); err != nil {
				t.Fatal(err)
			}
		}
		if warnings, err := cedarschema.DecodeSchemaWarnings(raw, 4096); err == nil {
			for _, entry := range warnings {
				if entry.Category == "" || entry.Severity != diagnostic.SeverityWarning {
					t.Fatal("invalid warning metadata")
				}
			}
		}
	})
}
