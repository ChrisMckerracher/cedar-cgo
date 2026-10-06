package validation_test

import (
	json "encoding/json"
	validation "github.com/ChrisMckerracher/cedar-go-wasm/cedar/validation"
	testing "testing"
)

func CloneValidationComparison(t testing.TB, result validation.ValidationResult) validation.ValidationResult {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var clone validation.ValidationResult
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
