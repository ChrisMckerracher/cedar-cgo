package integration_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"
	fuzz "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fuzz"
	joy "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzEntities(f *testing.F) {
	d := joy.LoadJoy(f)
	rt := testruntime.New(f)
	f.Add(string(fixture.MustReadFile(f, "../testdata/joy/entities.json")))
	f.Add(`[{"uid":{"__entity":{"type":"Joy::Device","id":"d"}},"attrs":{},"parents":[{"type":"Joy::Account","id":"a"}],"tags":{}}]`)
	f.Add(`[{"uid":{"type":"Joy::Action","id":"session.read"},"attrs":{},"parents":[]}]`)
	f.Fuzz(func(t *testing.T, TextValue string) {
		if fuzz.Nesting(TextValue) > fuzz.MaxFuzzNesting {
			t.Skip()
		}
		for _, schema := range []*cedarschema.Schema{&d.Schema, nil} {
			a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: schema, Policies: d.Old, Entities: cedarentity.EntitiesFromJSON([]byte(TextValue)), Limits: fuzz.FuzzLimits})
			fault.CheckNoFault(t, err)
			if !utf8.ValidString(TextValue) {
				fault.RequireUTF8InputError(t, err)
			}
			if err != nil {
				continue
			}
			resp, err := a.Authorize(context.Background(), joy.JoyRequest())
			a.Close()
			fault.CheckNoFault(t, err)
			if err != nil && resp.Decision != cedarrequest.Deny {
				t.Fatalf("error %v came with %v", err, resp.Decision)
			}
		}
	})
}
