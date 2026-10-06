package policy_test

import (
	context "context"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	jsonassert "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/jsonassert"
	reflect "reflect"
	slices "slices"
	strings "strings"
	testing "testing"
)

func CheckPolicySnapshot(t *testing.T, rt *cedar.Runtime, schema string, set cedarpolicy.ParsedPolicySet, want PolicySnapshot) {
	t.Helper()
	ctx := context.Background()
	jsonassert.Equal(t, set.JSON(), want.JSON)
	validation, err := rt.Validation().Validate(ctx, cedarschema.SchemaFromCedar(schema), set.Source())
	if err != nil {
		t.Fatal(err)
	}
	sortMessages := func(m []diagnostic.PolicyMessage) {
		slices.SortFunc(m, func(a, b diagnostic.PolicyMessage) int {
			if a.PolicyID != b.PolicyID {
				return strings.Compare(a.PolicyID, b.PolicyID)
			}
			return strings.Compare(a.Message, b.Message)
		})
	}
	sortMessages(validation.Errors)
	sortMessages(want.Errors)
	sortMessages(validation.Warnings)
	sortMessages(want.Warnings)
	if validation.Passed != want.Passed || !reflect.DeepEqual(validation.Errors, want.Errors) || !reflect.DeepEqual(validation.Warnings, want.Warnings) {
		t.Fatalf("validation differs: %+v vs %+v", validation, want)
	}
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: set.Source(), Entities: cedarentity.NewEntities(cedarentity.Entity{UID: entityuid.NewEntityUID("Photo", "p"), Attrs: cedarvalue.Record{"public": cedarvalue.Bool(true)}})})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for _, o := range want.Outcomes {
		response, err := a.Authorize(ctx, request.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "p"), Context: request.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(o.MFA)})})
		if err != nil {
			t.Fatal(err)
		}
		sortMessages(response.Errors)
		sortMessages(o.Errors)
		if response.Decision.String() != o.Decision || !slices.Equal(response.Reasons, o.Reasons) || !reflect.DeepEqual(response.Errors, o.Errors) {
			t.Fatalf("authorization differs: %+v vs %+v", response, o)
		}
	}
}
