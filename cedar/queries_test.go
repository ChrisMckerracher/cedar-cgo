package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type queryFixture struct {
	Name, Operation, Policies string
	PrincipalType             string `json:"principal_type"`
	ResourceType              string `json:"resource_type"`
	Principal, Resource       struct {
		Type string
		ID   *string
	}
	Action    cedar.EntityUID
	Context   *json.RawMessage
	Entities  *json.RawMessage
	Additions *json.RawMessage
	Replay    bool
}

func queryUID(value struct {
	Type string
	ID   *string
}) cedar.EntityUID {
	id := ""
	if value.ID != nil {
		id = *value.ID
	}
	return cedar.NewEntityUID(value.Type, id)
}
func queryPartialUID(value struct {
	Type string
	ID   *string
}) cedar.PartialEntityUID {
	if value.ID == nil {
		return cedar.UnknownEntityUID(value.Type)
	}
	return cedar.KnownEntityUID(queryUID(value))
}

func TestPermissionQueryNativeFixtures(t *testing.T) {
	var input struct {
		Schema, Policies string
		Entities         json.RawMessage
		Cases            []queryFixture
	}
	var expected []struct {
		Name               string
		Allowed, Undecided []cedar.EntityUID
		ErrorKind          cedar.ErrorKind          `json:"error_kind"`
		WithoutAdditions   *cedar.ActionQueryResult `json:"without_additions"`
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/queries/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/queries/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(input.Cases) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(input.Schema)
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
			a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(policies), Entities: cedar.EntitiesFromJSON(entities)})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			var contextValue cedar.Context
			var partialContext *cedar.Context
			if tc.Context != nil {
				contextValue = cedar.ContextFromJSON(*tc.Context)
				partialContext = &contextValue
			}
			runQuery := func(additions *json.RawMessage) (cedar.ActionQueryResult, error) {
				var concrete cedar.Entities
				var partial cedar.PartialEntities
				if additions != nil {
					concrete = cedar.EntitiesFromJSON(*additions)
					partial = cedar.PartialEntitiesFromJSON(*additions)
				}
				var result cedar.ActionQueryResult
				var err error
				switch tc.Operation {
				case "resource":
					result.Allowed, err = a.QueryResources(ctx, cedar.ResourceQueryRequest{Principal: queryUID(tc.Principal), Action: tc.Action, ResourceType: tc.ResourceType, Context: contextValue, Entities: concrete})
				case "principal":
					result.Allowed, err = a.QueryPrincipals(ctx, cedar.PrincipalQueryRequest{PrincipalType: tc.PrincipalType, Action: tc.Action, Resource: queryUID(tc.Resource), Context: contextValue, Entities: concrete})
				case "action":
					result, err = a.QueryActions(ctx, cedar.ActionQueryRequest{Principal: queryPartialUID(tc.Principal), Resource: queryPartialUID(tc.Resource), Context: partialContext, Entities: partial})
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
				var ce *cedar.Error
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
			var reparsed cedar.ActionQueryResult
			if err := json.Unmarshal(data, &reparsed); err != nil || !reflect.DeepEqual(result, reparsed) {
				t.Fatalf("query result JSON changed data: %+v %v", reparsed, err)
			}
			var additions cedar.Entities
			if tc.Additions != nil {
				additions = cedar.EntitiesFromJSON(*tc.Additions)
			}
			if tc.Name == "unsatisfiable-undecided" && len(result.Undecided) == 0 {
				t.Fatal("fixture must preserve unsatisfiable undecided candidate")
			}
			if tc.Operation == "resource" {
				for _, resource := range result.Allowed {
					response, err := a.Authorize(ctx, cedar.Request{Principal: queryUID(tc.Principal), Action: tc.Action, Resource: resource, Context: contextValue, Entities: additions})
					if err != nil || response.Decision != cedar.Allow {
						t.Fatalf("query replay %+v %v", response, err)
					}
				}
			}
			if tc.Operation == "principal" {
				for _, principal := range result.Allowed {
					response, err := a.Authorize(ctx, cedar.Request{Principal: principal, Action: tc.Action, Resource: queryUID(tc.Resource), Context: contextValue, Entities: additions})
					if err != nil || response.Decision != cedar.Allow {
						t.Fatalf("query replay %+v %v", response, err)
					}
				}
			}
			if tc.Replay {
				for _, action := range result.Allowed {
					response, err := a.Authorize(ctx, cedar.Request{Principal: queryUID(tc.Principal), Action: action, Resource: queryUID(tc.Resource), Context: contextValue, Entities: additions})
					if err != nil || response.Decision != cedar.Allow {
						t.Fatalf("action replay %+v %v", response, err)
					}
				}
			}
		})
	}
}

func TestPermissionQueryBoundaries(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User,resource: Photo,context:{}};`)
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(`permit(principal,action,resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	action := cedar.NewEntityUID("Action", "view")
	principal := cedar.NewEntityUID("User", "x")
	if _, err := a.QueryResources(ctx, cedar.ResourceQueryRequest{Principal: principal, Action: action, ResourceType: "Unknown"}); err == nil {
		t.Fatal("unknown resource type accepted")
	}
	result, err := a.QueryActions(ctx, cedar.ActionQueryRequest{Principal: cedar.UnknownEntityUID("Unknown"), Resource: cedar.UnknownEntityUID("Photo")})
	if err != nil || len(result.Allowed)+len(result.Undecided) != 0 {
		t.Fatalf("unknown type %+v %v", result, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	got, err := a.QueryResources(canceled, cedar.ResourceQueryRequest{Principal: principal, Action: action, ResourceType: "Photo"})
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancellation %+v %v", got, err)
	}
	noSchema, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: cedar.PoliciesFromCedar(`permit(principal,action,resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer noSchema.Close()
	_, err = noSchema.QueryActions(ctx, cedar.ActionQueryRequest{Principal: cedar.UnknownEntityUID("User"), Resource: cedar.UnknownEntityUID("Photo")})
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindSchema {
		t.Fatalf("missing schema %v", err)
	}
}
