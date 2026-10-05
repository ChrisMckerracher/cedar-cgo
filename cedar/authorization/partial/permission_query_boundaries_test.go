package partial_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	testing "testing"
)

func TestPermissionQueryBoundaries(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User,resource: Photo,context:{}};`)
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal,action,resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	action := entityuid.NewEntityUID("Action", "view")
	principal := entityuid.NewEntityUID("User", "x")
	if _, err := a.Partial().QueryResources(ctx, cedarpartial.ResourceQueryRequest{Principal: principal, Action: action, ResourceType: "Unknown"}); err == nil {
		t.Fatal("unknown resource type accepted")
	}
	result, err := a.Partial().QueryActions(ctx, cedarpartial.ActionQueryRequest{Principal: cedarpartial.UnknownEntityUID("Unknown"), Resource: cedarpartial.UnknownEntityUID("Photo")})
	if err != nil || len(result.Allowed)+len(result.Undecided) != 0 {
		t.Fatalf("unknown type %+v %v", result, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	got, err := a.Partial().QueryResources(canceled, cedarpartial.ResourceQueryRequest{Principal: principal, Action: action, ResourceType: "Photo"})
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancellation %+v %v", got, err)
	}
	noSchema, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: cedarpolicy.PoliciesFromCedar(`permit(principal,action,resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer noSchema.Close()
	_, err = noSchema.Partial().QueryActions(ctx, cedarpartial.ActionQueryRequest{Principal: cedarpartial.UnknownEntityUID("User"), Resource: cedarpartial.UnknownEntityUID("Photo")})
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindSchema {
		t.Fatalf("missing schema %v", err)
	}
}
