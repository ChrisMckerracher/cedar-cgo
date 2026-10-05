package integration_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzEntities(f *testing.F) {
	d := testsupport.LoadJoy(f)
	rt := testsupport.TestRuntime(f)
	f.Add(string(testsupport.ReadFile(f, "../testdata/joy/entities.json")))
	f.Add(`[{"uid":{"__entity":{"type":"Joy::Device","id":"d"}},"attrs":{},"parents":[{"type":"Joy::Account","id":"a"}],"tags":{}}]`)
	f.Add(`[{"uid":{"type":"Joy::Action","id":"session.read"},"attrs":{},"parents":[]}]`)
	f.Fuzz(func(t *testing.T, TextValue string) {
		if testsupport.Nesting(TextValue) > testsupport.MaxFuzzNesting {
			t.Skip()
		}
		for _, schema := range []*cedarschema.Schema{&d.Schema, nil} {
			a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: schema, Policies: d.Old, Entities: cedarentity.EntitiesFromJSON([]byte(TextValue)), Limits: testsupport.FuzzLimits})
			testsupport.CheckNoFault(t, err)
			if !utf8.ValidString(TextValue) {
				testsupport.RequireUTF8InputError(t, err)
			}
			if err != nil {
				continue
			}
			resp, err := a.Authorize(context.Background(), testsupport.JoyRequest())
			a.Close()
			testsupport.CheckNoFault(t, err)
			if err != nil && resp.Decision != cedarrequest.Deny {
				t.Fatalf("error %v came with %v", err, resp.Decision)
			}
		}
	})
}
