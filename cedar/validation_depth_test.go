package cedar_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
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
		cedar.ValidationResult
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/validation-depth/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/validation-depth/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input.Cases) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testRuntime(t)
	schema := cedar.SchemaFromCedar(input.Schema)
	for i, tc := range input.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			policies := cedar.PoliciesFromCedar(tc.Policies)
			var result cedar.ValidationResult
			var err error
			if tc.Level == nil {
				result, err = rt.Validate(context.Background(), schema, policies)
			} else {
				result, err = rt.ValidateWithLevel(context.Background(), schema, policies, *tc.Level)
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
