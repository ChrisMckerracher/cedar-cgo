package policy_test

import (
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	slices "slices"
)

func fuzzPolicyIDs(s cedarpolicy.ParsedPolicySet) []string {
	ids := make([]string, 0, 8)
	for _, p := range s.Policies() {
		ids = append(ids, p.ID())
	}
	slices.Sort(ids)
	return ids
}
