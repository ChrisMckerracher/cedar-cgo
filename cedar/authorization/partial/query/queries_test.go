package query_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
	permissionquery "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/query"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	reflect "reflect"
	testing "testing"
)

func TestPermissionQueryNativeFixtures(t *testing.T) {
	var input struct {
		Schema, Policies string
		Entities         json.RawMessage
		Cases            []QueryFixture
	}
	var expected []struct {
		Name               string
		Allowed, Undecided []entityuid.EntityUID
		ErrorKind          diagnostic.ErrorKind               `json:"error_kind"`
		WithoutAdditions   *permissionquery.ActionQueryResult `json:"without_additions"`
	}
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/queries/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/queries/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input.Cases) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testruntime.New(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(input.Schema)
	for i, tc := range input.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			policies := input.Policies
			if tc.Policies != "" {
				policies = tc.Policies
			}
			entities := input.Entities
			if tc.Entities != nil {
				entities = *tc.Entities
			}
			a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(policies), Entities: cedarentity.EntitiesFromJSON(entities)})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			var contextValue cedarrequest.Context
			var partialContext *cedarrequest.Context
			if tc.Context != nil {
				contextValue = cedarrequest.ContextFromJSON(*tc.Context)
				partialContext = &contextValue
			}
			runQuery := func(additions *json.RawMessage) (permissionquery.ActionQueryResult, error) {
				var concrete cedarentity.Entities
				var partial partialinput.PartialEntities
				if additions != nil {
					concrete = cedarentity.EntitiesFromJSON(*additions)
					partial = partialinput.PartialEntitiesFromJSON(*additions)
				}
				var result permissionquery.ActionQueryResult
				var err error
				switch tc.Operation {
				case "resource":
					result.Allowed, err = a.Queries().QueryResources(ctx, permissionquery.ResourceQueryRequest{Principal: QueryUID(tc.Principal), Action: tc.Action, ResourceType: tc.ResourceType, Context: contextValue, Entities: concrete})
				case "principal":
					result.Allowed, err = a.Queries().QueryPrincipals(ctx, permissionquery.PrincipalQueryRequest{PrincipalType: tc.PrincipalType, Action: tc.Action, Resource: QueryUID(tc.Resource), Context: contextValue, Entities: concrete})
				case "action":
					result, err = a.Queries().QueryActions(ctx, permissionquery.ActionQueryRequest{Principal: QueryPartialUID(tc.Principal), Resource: QueryPartialUID(tc.Resource), Context: partialContext, Entities: partial})
				default:
					t.Fatal("unknown fixture operation")
				}
				return result, err
			}
			result, err := runQuery(tc.Additions)
			want := expected[i]
			if tc.Name != want.Name {
				t.Fatal("fixture name differs")
			}
			if want.WithoutAdditions != nil {
				baseline, baselineErr := runQuery(nil)
				if baselineErr != nil || !reflect.DeepEqual(baseline, *want.WithoutAdditions) {
					t.Fatalf("per-query additions changed loaded entities: %+v %v; native %+v", baseline, baselineErr, want.WithoutAdditions)
				}
			}
			if want.ErrorKind != "" {
				var ce *diagnostic.Error
				if !errors.As(err, &ce) || ce.Kind != want.ErrorKind || len(result.Allowed)+len(result.Undecided) != 0 {
					t.Fatalf("invalid additions: %+v %v; native %s", result, err, want.ErrorKind)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(result.Allowed, want.Allowed) || !reflect.DeepEqual(result.Undecided, want.Undecided) {
				t.Fatalf("Go %+v; native %+v", result, want)
			}
			data, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var reparsed permissionquery.ActionQueryResult
			if err := json.Unmarshal(data, &reparsed); err != nil || !reflect.DeepEqual(result, reparsed) {
				t.Fatalf("query result JSON changed data: %+v %v", reparsed, err)
			}
			var additions cedarentity.Entities
			if tc.Additions != nil {
				additions = cedarentity.EntitiesFromJSON(*tc.Additions)
			}
			if tc.Name == "unsatisfiable-undecided" && len(result.Undecided) == 0 {
				t.Fatal("fixture must preserve unsatisfiable undecided candidate")
			}
			if tc.Operation == "resource" {
				for _, resource := range result.Allowed {
					response, err := a.Authorize(ctx, cedarrequest.Request{Principal: QueryUID(tc.Principal), Action: tc.Action, Resource: resource, Context: contextValue, Entities: additions})
					if err != nil || response.Decision != cedarrequest.Allow {
						t.Fatalf("query replay %+v %v", response, err)
					}
				}
			}
			if tc.Operation == "principal" {
				for _, principal := range result.Allowed {
					response, err := a.Authorize(ctx, cedarrequest.Request{Principal: principal, Action: tc.Action, Resource: QueryUID(tc.Resource), Context: contextValue, Entities: additions})
					if err != nil || response.Decision != cedarrequest.Allow {
						t.Fatalf("query replay %+v %v", response, err)
					}
				}
			}
			if tc.Replay {
				for _, action := range result.Allowed {
					response, err := a.Authorize(ctx, cedarrequest.Request{Principal: QueryUID(tc.Principal), Action: action, Resource: QueryUID(tc.Resource), Context: contextValue, Entities: additions})
					if err != nil || response.Decision != cedarrequest.Allow {
						t.Fatalf("action replay %+v %v", response, err)
					}
				}
			}
		})
	}
}
