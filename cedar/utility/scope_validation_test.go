package utility_test

import (
	context "context"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzScopeValidation(f *testing.F) {
	rt := testruntime.New(f)
	schema := cedarschema.SchemaFromCedar(FuzzUtilSchema)
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
		fault.CheckNoFault(t, err)
		if !utf8.ValidString(pType) || !utf8.ValidString(actionID) || !utf8.ValidString(rType) {
			RequireUtilKind(t, err, diagnostic.KindInput)
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
