package generator

import (
	json "encoding/json"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	validation "github.com/ChrisMckerracher/cedar-cgo/cedar/validation"
	rapid "pgregory.net/rapid"
	reflect "reflect"
	regexp "regexp"
	slices "slices"
	strings "strings"
)

// Upstream chooses the "did you mean" hint by hash iteration, so the suggested
// type varies between identical runs; it is excluded from the determinism claim.
var PropHelpHint = regexp.MustCompile("(help: did you mean `[^`]*`\\?)")

func PropStripHints(messages []diagnostic.PolicyMessage) []diagnostic.PolicyMessage {
	out := slices.Clone(messages)
	for i := range out {
		out[i].Message = PropHelpHint.ReplaceAllString(out[i].Message, "")
	}
	return out
}

// The API does not document diagnostic order, so compare as sorted multisets.
func PropSortedMessages(messages []diagnostic.PolicyMessage) []diagnostic.PolicyMessage {
	out := slices.Clone(messages)
	slices.SortFunc(out, func(a, b diagnostic.PolicyMessage) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return strings.Compare(string(x), string(y))
	})
	return out
}

// Native validation collects errors and warnings in HashSets and renders
// hash-chosen spelling hints, so normalize both before comparing results.
func PropStableValidation(result validation.ValidationResult) validation.ValidationResult {
	result.Errors = PropSortedMessages(PropStripHints(result.Errors))
	result.Warnings = PropSortedMessages(PropStripHints(result.Warnings))
	return result
}

func PropSameValidation(t *rapid.T, a, b validation.ValidationResult) {
	t.Helper()
	if !reflect.DeepEqual(PropStableValidation(a), PropStableValidation(b)) {
		t.Fatalf("validation is not deterministic: %+v vs %+v", a, b)
	}
}
