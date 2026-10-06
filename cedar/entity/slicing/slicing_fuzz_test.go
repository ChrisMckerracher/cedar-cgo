package slicing_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzSliceEntities(f *testing.F) {
	fixture := SliceFixtures(f)[0]
	f.Add([]byte(fixture.Entities))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"uid":{"type":"User","id":"alice"},"attrs":null,"parents":[]}]`))
	rt := testruntime.New(f)
	f.Fuzz(func(t *testing.T, entities []byte) {
		if len(entities) > 64<<10 || fuzz.Nesting(string(entities)) > 40 {
			t.Skip()
		}
		cfg, req := fixture.Input()
		cfg.Entities = cedarentity.EntitiesFromJSON(entities)
		cfg.MaxIterations = 4
		ctx, cancel := context.WithTimeout(context.Background(), fuzz.FuzzLimits.CallTimeout)
		defer cancel()
		result, err := rt.Slicing().SliceEntities(ctx, cfg, req)
		fault.CheckNoFault(t, err)
		if !utf8.Valid(entities) {
			fault.RequireUTF8InputError(t, err)
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
			checkCtx, checkCancel := context.WithTimeout(context.Background(), fuzz.FuzzLimits.CallTimeout)
			a, err := rt.NewAuthorizer(checkCtx, authorization.Config{Schema: &cfg.Schema, Policies: cfg.Policies, Entities: source, Limits: fuzz.FuzzLimits})
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
