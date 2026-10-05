package analysis

import "github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/report"

// Report holds one result per schema request environment.
type Report = report.Report

// Result records one schema environment and its concrete counterexample.
type Result = report.Result

// Counterexample contains a request checked by Cedar's concrete authorizer.
type Counterexample = report.Counterexample

// PolicyEvaluation records one policy's matching behavior and evaluation errors.
type PolicyEvaluation = report.PolicyEvaluation
