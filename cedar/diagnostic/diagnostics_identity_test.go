package diagnostic_test

import (
	validation "github.com/ChrisMckerracher/cedar-go-wasm/cedar/validation"
	strings "strings"
	testing "testing"
)

func TestValidationDiagnosticRequiresPolicyID(t *testing.T) {
	for _, group := range []string{"errors", "warnings"} {
		severity, passed := "error", "false"
		if group == "warnings" {
			severity, passed = "warning", "true"
		}
		for _, identity := range []string{"", `"policy_id":null,`} {
			message := `{` + identity + `"message":"diagnostic","category":"unexpected_type","severity":"` + severity + `"}`
			response := `{"passed":` + passed + `,"errors":[],"warnings":[],"schema_warnings":[]}`
			response = strings.Replace(response, `"`+group+`":[]`, `"`+group+`":[`+message+`]`, 1)
			if result, err := validation.DecodeValidation([]byte(response), 10, 10); err == nil {
				t.Fatalf("accepted missing %s policy ID: %+v", group, result)
			}
		}
	}
}

func TestValidationDiagnosticPreservesEmptyPolicyID(t *testing.T) {
	response := `{"passed":false,"errors":[{"policy_id":"","message":"diagnostic","category":"unexpected_type","severity":"error"}],"warnings":[],"schema_warnings":[]}`
	result, err := validation.DecodeValidation([]byte(response), 10, 10)
	if err != nil || len(result.Errors) != 1 || result.Errors[0].PolicyID != "" {
		t.Fatalf("empty policy ID changed: %+v %v", result, err)
	}
}
