package validation_test

import (
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	validation "github.com/ChrisMckerracher/cedar-go-wasm/cedar/validation"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
)

func TestValidationDepthNativeFixtures(t *testing.T) {
	var input struct {
		Schema string
		Cases  []struct {
			Name, Policies string
			Level          *uint32
		}
	}
	var expected []struct {
		Name string
		validation.ValidationResult
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/validation-depth/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/validation-depth/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input.Cases) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testsupport.TestRuntime(t)
	schema := cedarschema.SchemaFromCedar(input.Schema)
	for i, tc := range input.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			policies := cedarpolicy.PoliciesFromCedar(tc.Policies)
			var result validation.ValidationResult
			var err error
			if tc.Level == nil {
				result, err = rt.Validation().Validate(context.Background(), schema, policies)
			} else {
				result, err = rt.Validation().ValidateWithLevel(context.Background(), schema, policies, *tc.Level)
			}
			if err != nil {
				t.Fatal(err)
			}
			if expected[i].Name != tc.Name || !reflect.DeepEqual(result, expected[i].ValidationResult) {
				t.Fatalf("got %+v; native result %+v", result, expected[i])
			}
		})
	}
}
