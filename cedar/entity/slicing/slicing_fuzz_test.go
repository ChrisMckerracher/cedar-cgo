package slicing_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzSliceEntities(f *testing.F) {
	fixture := testsupport.SliceFixtures(f)[0]
	f.Add([]byte(fixture.Entities))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"uid":{"type":"User","id":"alice"},"attrs":null,"parents":[]}]`))
	rt := testsupport.TestRuntime(f)
	f.Fuzz(func(t *testing.T, entities []byte) {
		if len(entities) > 64<<10 || testsupport.Nesting(string(entities)) > 40 {
			t.Skip()
		}
		cfg, req := fixture.Input()
		cfg.Entities = cedarentity.EntitiesFromJSON(entities)
		cfg.MaxIterations = 4
		ctx, cancel := context.WithTimeout(context.Background(), testsupport.FuzzLimits.CallTimeout)
		defer cancel()
		result, err := rt.Slicing().SliceEntities(ctx, cfg, req)
		testsupport.CheckNoFault(t, err)
		if !utf8.Valid(entities) {
			testsupport.RequireUTF8InputError(t, err)
			if result.Decision != cedarrequest.Deny || !result.Entities.IsZero() || len(result.Batches) != 0 {
				t.Fatalf("malformed slice leaked result: %+v", result)
			}
			return
		}
		if err != nil {
			if result.Decision != cedarrequest.Deny || !result.Entities.IsZero() || len(result.Batches) != 0 {
				t.Fatalf("failed slice leaked result: %+v, %v", result, err)
			}
			return
		}
		// Independent ordinary authorization must agree with the selected data.
		for _, source := range []cedarentity.Entities{cfg.Entities, result.Entities} {
			checkCtx, checkCancel := context.WithTimeout(context.Background(), testsupport.FuzzLimits.CallTimeout)
			a, err := rt.NewAuthorizer(checkCtx, authorization.Config{Schema: &cfg.Schema, Policies: cfg.Policies, Entities: source, Limits: testsupport.FuzzLimits})
			if err != nil {
				checkCancel()
				t.Fatal(err)
			}
			response, err := a.Authorize(checkCtx, req)
			a.Close()
			checkCancel()
			if err != nil || response.Decision != result.Decision {
				t.Fatalf("authorization disagrees with slice: %+v, %v, slice=%+v", response, err, result)
			}
		}
	})
}
