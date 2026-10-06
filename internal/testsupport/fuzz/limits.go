package fuzz

import (
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	time "time"
)

// Generous budgets distinguish small-input crashes from expected resource-limit faults.
var FuzzLimits = authorization.Limits{MaxInstances: 1, CallTimeout: 10 * time.Second}

// Skip deep nesting because stack exhaustion has its own fail-closed test.
func Nesting(s string) int {
	depth, deepest := 0, 0
	for _, r := range s {
		switch r {
		case '(', '[', '{':
			depth++
			deepest = max(deepest, depth)
		case ')', ']', '}':
			depth--
		}
	}
	return deepest
}

const MaxFuzzNesting = 200
