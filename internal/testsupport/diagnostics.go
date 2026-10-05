package testsupport

import (
	json "encoding/json"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	slices "slices"
	strings "strings"
)

func StableDiagnostics(values []diagnostic.PolicyMessage) []diagnostic.PolicyMessage {
	result := slices.Clone(values)
	for i := range result {
		result[i].Message = strings.Split(result[i].Message, " (help: did you mean")[0]
	}
	slices.SortFunc(result, func(a, b diagnostic.PolicyMessage) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return strings.Compare(string(x), string(y))
	})
	return result
}
