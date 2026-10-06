package partial

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"
	testing "testing"
)

type PartialFixtureRequest struct {
	Principal partialinput.PartialEntityUID
	Action    entityuid.EntityUID
	Resource  partialinput.PartialEntityUID
	Context   json.RawMessage
	Entities  json.RawMessage
}

func (r PartialFixtureRequest) Partial() partialinput.PartialRequest {
	var ctx *request.Context
	if string(r.Context) != "null" {
		c := request.ContextFromJSON(r.Context)
		ctx = &c
	}
	return partialinput.PartialRequest{
		Principal: r.Principal, Action: r.Action, Resource: r.Resource, Context: ctx,
		Entities: partialinput.PartialEntitiesFromJSON(r.Entities),
	}
}

func (r PartialFixtureRequest) Concrete() request.Request {
	return request.Request{
		Principal: entityuid.NewEntityUID(r.Principal.Type, *r.Principal.ID), Action: r.Action,
		Resource: entityuid.NewEntityUID(r.Resource.Type, *r.Resource.ID),
		Context:  request.ContextFromJSON(r.Context), Entities: cedarentity.EntitiesFromJSON(r.Entities),
	}
}

type PartialFixtureResult struct {
	ErrorStage    string `json:"error_stage"`
	Decision      string
	Reasons       []string
	Residuals     []cedarpartial.ResidualPolicy
	ErrorPolicies []string `json:"error_policies"`
	Completions   []PartialFixtureResult
	Projection    cedarpartial.ResidualProjection
}

func RequirePartialError(t testing.TB, response cedarpartial.PartialResponse, err error, kind diagnostic.ErrorKind) {
	t.Helper()
	var ce *diagnostic.Error
	if response.Decision != cedarpartial.Undecided || !errors.As(err, &ce) || ce.Kind != kind {
		t.Fatalf("got %+v, %v; want undecided and %s", response, err, kind)
	}
}

const PartialSchema = `entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {mfa: Bool} };`

func PartialRequest() partialinput.PartialRequest {
	return partialinput.PartialRequest{
		Principal: partialinput.UnknownEntityUID("User"), Action: entityuid.NewEntityUID("Action", "view"), Resource: partialinput.UnknownEntityUID("Photo"),
	}
}

func PartialAuthorizer(t testing.TB, limits authorization.Limits) *authorization.Authorizer {
	t.Helper()
	schema := cedarschema.SchemaFromCedar(PartialSchema)
	a, err := testruntime.New(t).NewAuthorizer(context.Background(), authorization.Config{
		Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar("permit(principal, action, resource) when { context.mfa };"), Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}
