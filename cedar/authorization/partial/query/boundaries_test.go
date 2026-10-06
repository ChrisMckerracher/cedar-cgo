package query_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
	permissionquery "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/query"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func TestPermissionQueryBoundaries(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User,resource: Photo,context:{}};`)
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal,action,resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	action := entityuid.NewEntityUID("Action", "view")
	principal := entityuid.NewEntityUID("User", "x")
	if _, err := a.Queries().QueryResources(ctx, permissionquery.ResourceQueryRequest{Principal: principal, Action: action, ResourceType: "Unknown"}); err == nil {
		t.Fatal("unknown resource type accepted")
	}
	result, err := a.Queries().QueryActions(ctx, permissionquery.ActionQueryRequest{Principal: partialinput.UnknownEntityUID("Unknown"), Resource: partialinput.UnknownEntityUID("Photo")})
	if err != nil || len(result.Allowed)+len(result.Undecided) != 0 {
		t.Fatalf("unknown type %+v %v", result, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	got, err := a.Queries().QueryResources(canceled, permissionquery.ResourceQueryRequest{Principal: principal, Action: action, ResourceType: "Photo"})
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancellation %+v %v", got, err)
	}
	noSchema, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: cedarpolicy.PoliciesFromCedar(`permit(principal,action,resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer noSchema.Close()
	_, err = noSchema.Queries().QueryActions(ctx, permissionquery.ActionQueryRequest{Principal: partialinput.UnknownEntityUID("User"), Resource: partialinput.UnknownEntityUID("Photo")})
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindSchema {
		t.Fatalf("missing schema %v", err)
	}
}
