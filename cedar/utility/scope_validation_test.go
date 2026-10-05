package utility_test

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzScopeValidation(f *testing.F) {
	rt := testsupport.TestRuntime(f)
	schema := cedarschema.SchemaFromCedar(testsupport.FuzzUtilSchema)
	f.Add("User", "view", "Photo")
	f.Add("Photo", "view", "Photo")
	f.Add("User", "edit", "Photo")
	f.Add("\xff", "view", "Photo")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, pType, actionID, rType string) {
		if len(pType)+len(actionID)+len(rType) > 1<<20 {
			t.Skip()
		}
		err := rt.Utilities().ValidateScopeVariables(context.Background(), schema,
			entityuid.NewEntityUID(pType, "x"), entityuid.NewEntityUID("Action", actionID), entityuid.NewEntityUID(rType, "p"))
		testsupport.CheckNoFault(t, err)
		if !utf8.ValidString(pType) || !utf8.ValidString(actionID) || !utf8.ValidString(rType) {
			testsupport.RequireUtilKind(t, err, diagnostic.KindInput)
			return
		}
		if pType == "User" && actionID == "view" && rType == "Photo" {
			if err != nil {
				t.Fatalf("fitting scope rejected: %v", err)
			}
			return
		}
		// Malformed type tokens fail principal/resource parsing; well-formed
		// ones miss the action's declared request environment.
		var ce *diagnostic.Error
		if !errors.As(err, &ce) ||
			(ce.Kind != diagnostic.KindRequest && ce.Kind != diagnostic.KindPrincipal && ce.Kind != diagnostic.KindResource) {
			t.Fatalf("scope %q/%q/%q: %v", pType, actionID, rType, err)
		}
	})
}
