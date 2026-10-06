package slicing_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	slicing "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/slicing"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"

	reflect "reflect"
	testing "testing"
)

func TestSliceEntitiesNativeParity(t *testing.T) {
	var expected []struct {
		Name     string
		Decision string
		Entities json.RawMessage
		Batches  [][]entityuid.EntityUID
	}
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/slicing/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	fixtures := SliceFixtures(t)
	if len(fixtures) != len(expected) {
		t.Fatal("regenerate slicing native fixtures")
	}
	for i, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			cfg, req := fixture.Input()
			ctx := context.Background()
			rt := testruntime.New(t)
			result, err := rt.Slicing().SliceEntities(ctx, cfg, req)
			if err != nil {
				t.Fatal(err)
			}
			want := expected[i]
			if fixture.Name != want.Name || result.Decision.String() != want.Decision || !reflect.DeepEqual(result.Batches, want.Batches) {
				t.Fatalf("native mismatch: result=%+v, expected=%+v", result, want)
			}
			gotEntities, err := json.Marshal(result.Entities)
			if err != nil {
				t.Fatal(err)
			}
			if CanonicalEntities(t, gotEntities) != CanonicalEntities(t, want.Entities) {
				t.Fatalf("entity slice differs from native\ngot %s\nwant %s", gotEntities, want.Entities)
			}
			for name, entities := range map[string]cedarentity.Entities{"full": cfg.Entities, "slice": result.Entities} {
				a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &cfg.Schema, Policies: cfg.Policies, Entities: entities})
				if err != nil {
					t.Fatal(err)
				}
				resp, err := a.Authorize(ctx, req)
				a.Close()
				if err != nil || resp.Decision != result.Decision {
					t.Fatalf("%s authorization: %+v, %v; slice decision=%v", name, resp, err, result.Decision)
				}
			}
		})
	}
}

func TestSliceEntitiesBoundaries(t *testing.T) {
	rt := testruntime.New(t)
	fixtures := SliceFixtures(t)
	cases := []struct {
		name string
		edit func(*slicing.SliceConfig, *cedarrequest.Request)
		kind diagnostic.ErrorKind
	}{
		{"invalid schema", func(c *slicing.SliceConfig, _ *cedarrequest.Request) {
			c.Schema = cedarschema.SchemaFromCedar("invalid")
		}, diagnostic.KindSchema},
		{"invalid policies", func(c *slicing.SliceConfig, _ *cedarrequest.Request) {
			c.Policies = cedarpolicy.PoliciesFromCedar("invalid")
		}, diagnostic.KindPolicies},
		{"unvalidated policy", func(c *slicing.SliceConfig, _ *cedarrequest.Request) {
			c.Policies = cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { principal.profile.active == 1 };`)
		}, diagnostic.KindSlicing},
		{"invalid entity", func(c *slicing.SliceConfig, _ *cedarrequest.Request) {
			c.Entities = cedarentity.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"bad"},"attrs":{},"parents":[]}]`))
		}, diagnostic.KindEntities},
		{"invalid JSON", func(c *slicing.SliceConfig, _ *cedarrequest.Request) {
			c.Entities = cedarentity.EntitiesFromJSON([]byte(`[`))
		}, diagnostic.KindInput},
		{"invalid UID", func(_ *slicing.SliceConfig, r *cedarrequest.Request) { r.Principal.Type = "!!!" }, diagnostic.KindPrincipal},
		{"invalid context", func(_ *slicing.SliceConfig, r *cedarrequest.Request) {
			r.Context = cedarrequest.NewContext(cedarvalue.Record{"bypass": cedarvalue.Long(1)})
		}, diagnostic.KindRequest},
		{"context is not a record", func(_ *slicing.SliceConfig, r *cedarrequest.Request) {
			r.Context = cedarrequest.ContextFromJSON([]byte(`[]`))
		}, diagnostic.KindContext},
		{"invalid request", func(_ *slicing.SliceConfig, r *cedarrequest.Request) {
			r.Principal = entityuid.NewEntityUID("Doc", "report")
		}, diagnostic.KindRequest},
		{"iteration exhaustion", func(c *slicing.SliceConfig, _ *cedarrequest.Request) { c.MaxIterations = 1 }, diagnostic.KindSlicing},
		{"conflicting entity", func(_ *slicing.SliceConfig, r *cedarrequest.Request) {
			r.Entities = cedarentity.NewEntities(cedarentity.Entity{UID: entityuid.NewEntityUID("User", "alice"), Attrs: cedarvalue.Record{"profile": cedarvalue.Record{"active": cedarvalue.Bool(false), "label": cedarvalue.String("conflict")}}})
		}, diagnostic.KindEntities},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg, req := fixtures[1].Input()
			test.edit(&cfg, &req)
			result, err := rt.Slicing().SliceEntities(context.Background(), cfg, req)
			var ce *diagnostic.Error
			if !errors.As(err, &ce) || ce.Kind != test.kind || result.Decision != cedarrequest.Deny || !result.Entities.IsZero() || len(result.Batches) != 0 {
				t.Fatalf("expected %s with empty denying result, got %+v / %v", test.kind, result, err)
			}
		})
	}
	// A successful call after failures must not inherit any previous loader state.
	cfg, req := fixtures[0].Input()
	if _, err := rt.Slicing().SliceEntities(context.Background(), cfg, req); err != nil {
		t.Fatal(err)
	}
}
