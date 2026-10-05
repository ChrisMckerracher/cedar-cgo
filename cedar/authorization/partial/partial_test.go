package partial_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
)

func TestPartialNativeFixtures(t *testing.T) {
	var input struct {
		Schema string
		Cases  []struct {
			Name, Policies string
			PoliciesJSON   json.RawMessage `json:"policies_json"`
			Loaded         json.RawMessage
			Partial        testsupport.PartialFixtureRequest
			Completions    []testsupport.PartialFixtureRequest
		}
	}
	var expected []struct {
		Name   string
		Result testsupport.PartialFixtureResult
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/partial/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/partial/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(input.Cases) {
		t.Fatal("fixture count mismatch")
	}
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(input.Schema)
	for i, tc := range input.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			want := expected[i]
			if want.Name != tc.Name {
				t.Fatal("fixture order mismatch")
			}
			policies := cedarpolicy.PoliciesFromCedar(tc.Policies)
			if tc.PoliciesJSON != nil {
				policies = cedarpolicy.PoliciesFromJSON(tc.PoliciesJSON)
			}
			a, err := testsupport.TestRuntime(t).NewAuthorizer(ctx, authorization.Config{
				Schema: &schema, Policies: policies, Entities: cedarentity.EntitiesFromJSON(tc.Loaded),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			got, err := a.Partial().PartialAuthorize(ctx, tc.Partial.Partial())
			if want.Result.ErrorStage != "" {
				testsupport.RequirePartialError(t, got, err, diagnostic.ErrorKind(want.Result.ErrorStage))
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision.String() != want.Result.Decision || !reflect.DeepEqual(got.Reasons, want.Result.Reasons) || !reflect.DeepEqual(got.Residuals, want.Result.Residuals) {
				t.Fatalf("Go/native disagreement:\n got %+v\nwant %+v", got, want.Result)
			}
			gotProjection, err := json.Marshal(got.Projection())
			if err != nil {
				t.Fatal(err)
			}
			wantProjection, err := json.Marshal(want.Result.Projection)
			if err != nil {
				t.Fatal(err)
			}
			testsupport.AssertSchemaJSON(t, gotProjection, wantProjection)
			exported, err := got.Export()
			if err != nil {
				t.Fatal(err)
			}
			imported, err := a.Partial().ImportPartialResponse(ctx, exported)
			if err != nil {
				t.Fatal(err)
			}
			if imported.Decision != got.Decision || !reflect.DeepEqual(imported.Residuals, got.Residuals) {
				t.Fatal("imported residual response differs")
			}
			if len(tc.Completions) != len(want.Result.Completions) {
				t.Fatal("completion count mismatch")
			}
			for j, c := range tc.Completions {
				r, err := got.Reauthorize(ctx, c.Concrete())
				replayed, replayErr := imported.Reauthorize(ctx, c.Concrete())
				if (err == nil) != (replayErr == nil) || !reflect.DeepEqual(r, replayed) {
					t.Fatalf("imported replay differs: %+v %v; %+v %v", r, err, replayed, replayErr)
				}
				w := want.Result.Completions[j]
				if w.ErrorStage != "" {
					var ce *diagnostic.Error
					if r.Decision != cedarrequest.Deny || !errors.As(err, &ce) || string(ce.Kind) != w.ErrorStage {
						t.Fatalf("completion %d: %+v %v, want %s", j, r, err, w.ErrorStage)
					}
					continue
				}
				ids := make([]string, 0, len(r.Errors))
				for _, e := range r.Errors {
					ids = append(ids, e.PolicyID)
				}
				if err != nil || r.Decision.String() != w.Decision || !reflect.DeepEqual(r.Reasons, w.Reasons) || !reflect.DeepEqual(ids, w.ErrorPolicies) {
					t.Fatalf("completion %d: %+v %v, want %+v", j, r, err, w)
				}
			}
		})
	}
}
