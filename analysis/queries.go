package analysis

import (
	"context"

	"github.com/ChrisMckerracher/cedar-cgo/analysis/report"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

// NewlyPermitted holds when after permits nothing new; a counterexample is newly allowed.
// Both sets must pass strict validation against schema and contain no templates.
func (a *Analyzer) NewlyPermitted(ctx context.Context, schema schemas.Schema, before, after policy.PolicySet) (report.Report, error) {
	// Reverse implication proves that after is a subset of before.
	return a.run(ctx, "implies", schema, after, before, true)
}

// Equivalent asks whether x and y give the same decision on every request.
// A counterexample is a request on which they differ.
func (a *Analyzer) Equivalent(ctx context.Context, schema schemas.Schema, x, y policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "equivalent", schema, x, y, false)
}

// NeverErrors checks one policy for evaluation errors on schema-valid requests.
func (a *Analyzer) NeverErrors(ctx context.Context, schema schemas.Schema, policies policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "never_errors", schema, policies, policy.PolicySet{}, false)
}

// AlwaysMatches checks whether one policy matches every schema-valid request.
func (a *Analyzer) AlwaysMatches(ctx context.Context, schema schemas.Schema, policies policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "always_matches", schema, policies, policy.PolicySet{}, false)
}

// NeverMatches checks whether one policy matches no schema-valid requests.
func (a *Analyzer) NeverMatches(ctx context.Context, schema schemas.Schema, policies policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "never_matches", schema, policies, policy.PolicySet{}, false)
}

// MatchesEquivalent compares native matching behavior for permit and forbid policies.
func (a *Analyzer) MatchesEquivalent(ctx context.Context, schema schemas.Schema, x, y policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "matches_equivalent", schema, x, y, false)
}

// MatchesImplies checks whether matching x always implies matching y.
func (a *Analyzer) MatchesImplies(ctx context.Context, schema schemas.Schema, x, y policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "matches_implies", schema, x, y, false)
}

// MatchesDisjoint checks whether two policies can never both match one request.
func (a *Analyzer) MatchesDisjoint(ctx context.Context, schema schemas.Schema, x, y policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "matches_disjoint", schema, x, y, false)
}

// Disjoint checks whether two policy sets can never both allow one request.
func (a *Analyzer) Disjoint(ctx context.Context, schema schemas.Schema, x, y policy.PolicySet) (report.Report, error) {
	return a.run(ctx, "disjoint", schema, x, y, false)
}
