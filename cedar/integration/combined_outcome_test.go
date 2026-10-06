package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/batched"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/slicing"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	"testing"
)

type combinedScenario struct {
	rt                          *cedar.Runtime
	a                           *authorization.Authorizer
	partial                     cedarpartial.PartialResponse
	schema                      cedarschema.Schema
	policies                    cedarpolicy.PolicySet
	store                       map[entityuid.EntityUID]cedarentity.Entity
	full                        cedarentity.Entities
	principal, action, resource entityuid.EntityUID
}

func checkCombinedOutcome(t *testing.T, scenario combinedScenario, mfa bool, want cedarrequest.Decision, reason string) {
	ctx := context.Background()

	checkResponse := func(path string, response cedarrequest.Response, err error) {
		t.Helper()
		if err != nil || response.Decision != want || len(response.Errors) != 0 || len(response.Reasons) != 1 || response.Reasons[0] != reason {
			t.Fatalf("%s: %+v, %v; want %s with raw reason %q", path, response, err, want, reason)
		}
	}
	req := cedarrequest.Request{Principal: scenario.principal, Action: scenario.action, Resource: scenario.resource,
		Context: cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(mfa)}), Entities: scenario.full}
	response, err := scenario.a.Authorize(ctx, req)
	checkResponse("ordinary", response, err)
	response, err = scenario.partial.Reauthorize(ctx, req)
	checkResponse("reauthorize", response, err)

	// The callback must supply data even after ordinary calls used full request entities.
	req.Entities = cedarentity.Entities{}
	calls := 0
	decision, err := scenario.a.Batched().AuthorizeBatched(ctx, req, batched.EntityLoaderFunc(func(_ context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
		calls++
		entities := make([]cedarentity.Entity, 0, len(uids))
		for _, uid := range uids {
			entity, ok := scenario.store[uid]
			if !ok {
				return batched.EntityLoadResult{}, fmt.Errorf("unexpected requested entity: %v", uid)
			}
			entities = append(entities, entity)
		}
		data, err := json.Marshal(cedarentity.NewEntities(entities...))
		return batched.EntityLoadResult{Entities: data}, err
	}), batched.BatchedOptions{MaxIterations: 4})
	if err != nil || decision != want || (mfa && calls == 0) {
		t.Fatalf("batched: %s, %v, callbacks=%d; want %s", decision, err, calls, want)
	}
	slice, err := scenario.rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{Schema: scenario.schema, Policies: scenario.policies, Entities: scenario.full}, req)
	if err != nil || slice.Decision != want {
		t.Fatalf("slice: %+v, %v; want %s", slice, err, want)
	}
	data, err := json.Marshal(slice.Entities)
	if err != nil {
		t.Fatal(err)
	}
	var retained []json.RawMessage
	if err := json.Unmarshal(data, &retained); err != nil || len(retained) >= 3 || (mfa && (len(retained) != 2 || len(slice.Batches) == 0)) {
		t.Fatalf("expected a request-specific reduction: entities=%s, batches=%v, err=%v", data, slice.Batches, err)
	}
	// A fresh authorizer prevents full request data or callback caches from masking a bad slice.
	reduced, err := scenario.rt.NewAuthorizer(ctx, authorization.Config{Schema: &scenario.schema, Policies: scenario.policies, Entities: slice.Entities})
	if err != nil {
		t.Fatal(err)
	}
	defer reduced.Close()
	response, err = reduced.Authorize(ctx, req)
	// Slicing preserves decisions; errors from policies irrelevant to that decision may differ.
	if err != nil || response.Decision != want {
		t.Fatalf("reduced: %+v, %v; want %s", response, err, want)
	}
}
