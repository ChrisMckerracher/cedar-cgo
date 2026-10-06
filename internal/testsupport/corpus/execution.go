package corpus

import (
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"

	bytes "bytes"
	context "context"
	json "encoding/json"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"

	filepath "path/filepath"
	slices "slices"
)

func RunCorpusTest(rt *cedar.Runtime, dir, file string, tally *CorpusTally) {
	ctx := context.Background()
	name := filepath.Base(file)
	read := func(rel string) []byte {
		b, err := fixture.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			tally.Note(&tally.SetupFailure, "%s: %v", name, err)
		}
		return b
	}
	raw, err := fixture.ReadFile(file)
	if err != nil {
		tally.Note(&tally.SetupFailure, "%s: %v", name, err)
		return
	}
	var tt CorpusTest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tt); err != nil {
		tally.Note(&tally.SetupFailure, "%s: decode test: %v", name, err)
		return
	}
	tally.Mu.Lock()
	tally.Tests++
	tally.Requests += len(tt.Requests)
	tally.Mu.Unlock()

	schema := ParseSchema(tt.SchemaFormat, string(read(tt.Schema)))
	policies := ParsePolicies(tt.PolicyFormat, string(read(tt.Policies)))
	entities := cedarentity.EntitiesFromJSON(read(tt.Entities))

	res, err := rt.Validation().Validate(ctx, schema, policies)
	switch {
	case err != nil:
		tally.Note(&tally.ValidationMismatch, "%s: validate: %v", name, err)
	case res.Passed != tt.ShouldValidate:
		tally.Note(&tally.ValidationMismatch, "%s: strict validation passed=%v, corpus says %v: %+v", name, res.Passed, tt.ShouldValidate, res.Errors)
	}

	a, err := rt.NewAuthorizer(ctx, authorization.Config{
		Schema:   &schema,
		Policies: policies,
		Entities: entities,
		Limits:   authorization.Limits{MaxInstances: 1, CallTimeout: -1},
	})
	if err != nil {
		tally.Note(&tally.SetupFailure, "%s: load: %v", name, err)
		return
	}
	defer a.Close()

	for _, r := range tt.Requests {
		if r.ValidateRequest != nil && !*r.ValidateRequest {
			tally.Note(&tally.RequestFailure, "%s: %s: validateRequest=false is not supported", name, r.Description)
			continue
		}
		resp, err := a.Authorize(ctx, request.Request{
			Principal: r.Principal.EntityUID,
			Action:    r.Action.EntityUID,
			Resource:  r.Resource.EntityUID,
			Context:   request.ContextFromJSON(r.Context),
		})
		if err != nil {
			tally.Note(&tally.RequestFailure, "%s: %s: %v", name, r.Description, err)
			continue
		}
		if resp.Decision.String() != r.Decision {
			tally.Note(&tally.DecisionMismatch, "%s: %s: decision %s, corpus says %s", name, r.Description, resp.Decision, r.Decision)
		}
		if !SameSet(resp.Reasons, r.Reason) {
			tally.Note(&tally.ReasonMismatch, "%s: %s: reasons %v, corpus says %v", name, r.Description, resp.Reasons, r.Reason)
		}
		var errIDs []string
		for _, e := range resp.Errors {
			errIDs = append(errIDs, e.PolicyID)
		}
		if !SameSet(errIDs, r.Errors) {
			tally.Note(&tally.ErrorMismatch, "%s: %s: errors %v, corpus says %v", name, r.Description, errIDs, r.Errors)
		}
	}
}

// Ignore policy-ID order to match cedar-testing's comparison.
func SameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
