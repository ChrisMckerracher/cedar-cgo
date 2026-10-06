package compiled

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"

	decoded "github.com/ChrisMckerracher/cedar-go-wasm/analysis/internal/report"
	reports "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
)

func (s *Session) check(ctx context.Context, query string, first, second PolicySet) (reports.Report, error) {
	if s == nil || s.gate == nil {
		return reports.Report{}, ErrClosed
	}
	input, err := s.encodeCompiled(compiledInput{Operation: "check", Query: query, First: first.id, Second: second.id})
	if err != nil {
		return reports.Report{}, err
	}
	var report reports.Report
	err = s.execute(ctx, input, func() error {
		if err := s.validateHandle(first); err != nil {
			return err
		}
		return s.validateHandle(second)
	}, func(data []byte) error {
		var result struct {
			Report jsontext.Value `json:"report"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return err
		}
		if len(result.Report) == 0 {
			return errors.New("compiled response has no report")
		}
		var envelope map[string]jsontext.Value
		if err := json.Unmarshal(result.Report, &envelope); err != nil {
			return err
		}
		if _, present := envelope["results"]; !present || len(envelope) != 1 {
			return errors.New("compiled report has an invalid envelope")
		}
		var err error
		report, err = decoded.Decode(result.Report, false, query)
		if err != nil {
			return err
		}
		if len(report.Results) != len(s.environments) {
			return errors.New("compiled response has the wrong environment count")
		}
		for i, result := range report.Results {
			env := s.environments[i]
			if result.PrincipalType != env.PrincipalType || result.Action.Type != env.Action.Type || result.Action.ID != env.Action.ID || result.ResourceType != env.ResourceType {
				return errors.New("compiled response has the wrong environment")
			}
		}
		return nil
	})
	if err != nil {
		return reports.Report{}, err
	}
	return report, nil
}

// Implies checks whether every request allowed by first is also allowed by second.
func (s *Session) Implies(ctx context.Context, first, second PolicySet) (reports.Report, error) {
	return s.check(ctx, "implies", first, second)
}

// Equivalent checks whether both compiled policy sets always produce the same decision.
func (s *Session) Equivalent(ctx context.Context, first, second PolicySet) (reports.Report, error) {
	return s.check(ctx, "equivalent", first, second)
}

// Disjoint checks whether no request is allowed by both compiled policy sets.
func (s *Session) Disjoint(ctx context.Context, first, second PolicySet) (reports.Report, error) {
	return s.check(ctx, "disjoint", first, second)
}
