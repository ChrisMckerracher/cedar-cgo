package policy

import (
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	testing "testing"
)

func PartialIDPolicy(effect, kind, body string) json.RawMessage {
	return json.RawMessage(`{"effect":"` + effect + `","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"` + kind + `","body":` + body + `}]}`)
}

func PartialIDPolicies(t *testing.T, policies map[string]json.RawMessage) cedarpolicy.PolicySet {
	t.Helper()
	data, err := json.Marshal(map[string]any{"staticPolicies": policies, "templates": map[string]any{}, "templateLinks": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	return cedarpolicy.PoliciesFromJSON(data)
}
