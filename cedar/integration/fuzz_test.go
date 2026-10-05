package integration_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzAuthorize(f *testing.F) {
	d := testsupport.LoadJoy(f)
	a, err := testsupport.TestRuntime(f).NewAuthorizer(context.Background(), authorization.Config{
		Schema: &d.Schema, Policies: d.Old, Entities: d.Entities, Limits: testsupport.FuzzLimits,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(a.Close)
	ctxJSON, _ := testsupport.JoyContext().MarshalJSON()
	f.Add("Joy::Device", "phone1", "session.write", "Joy::Session", "s1", string(ctxJSON), "")
	f.Add("Joy::Device", "phone1", "terminal.open", "Joy::Project", "proj1", `{"deviceLevel":2}`, `[{"uid":{"type":"Joy::Device","id":"x"},"attrs":{},"parents":[]}]`)
	f.Add("Joy::Device", "", "file.read", "Joy::Session", "\x00", `{"now":{"__extn":{"fn":"datetime","arg":"1969-12-31"}}}`, `[]`)
	f.Fuzz(func(t *testing.T, pType, pID, action, rType, rID, ctxJSON, entJSON string) {
		if testsupport.Nesting(ctxJSON) > testsupport.MaxFuzzNesting || testsupport.Nesting(entJSON) > testsupport.MaxFuzzNesting {
			t.Skip()
		}
		req := cedarrequest.Request{
			Principal: entityuid.NewEntityUID(pType, pID),
			Action:    entityuid.NewEntityUID("Joy::Action", action),
			Resource:  entityuid.NewEntityUID(rType, rID),
			Context:   cedarrequest.ContextFromJSON([]byte(ctxJSON)),
		}
		if entJSON != "" {
			req.Entities = cedarentity.EntitiesFromJSON([]byte(entJSON))
		}
		resp, err := a.Authorize(context.Background(), req)
		testsupport.CheckNoFault(t, err)
		for _, TextValue := range []string{pType, pID, action, rType, rID, ctxJSON, entJSON} {
			if !utf8.ValidString(TextValue) {
				testsupport.RequireUTF8InputError(t, err)
			}
		}
		if err != nil && resp.Decision != cedarrequest.Deny {
			t.Fatalf("error %v came with %v", err, resp.Decision)
		}
	})
}
