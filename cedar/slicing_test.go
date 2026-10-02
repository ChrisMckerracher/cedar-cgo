package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type sliceFixture struct {
	Name     string
	Schema   json.RawMessage
	Policies string
	Entities json.RawMessage
	Request  struct {
		Principal cedar.EntityUID
		Action    cedar.EntityUID
		Resource  cedar.EntityUID
		Context   json.RawMessage
	}
}

func (f sliceFixture) input() (cedar.SliceConfig, cedar.Request) {
	schema := cedar.SchemaFromJSON(f.Schema)
	var text string
	if json.Unmarshal(f.Schema, &text) == nil {
		schema = cedar.SchemaFromCedar(text)
	}
	return cedar.SliceConfig{Schema: schema, Policies: cedar.PoliciesFromCedar(f.Policies), Entities: cedar.EntitiesFromJSON(f.Entities)},
		cedar.Request{Principal: f.Request.Principal, Action: f.Request.Action, Resource: f.Request.Resource, Context: cedar.ContextFromJSON(f.Request.Context)}
}

func sliceFixtures(t testing.TB) []sliceFixture {
	t.Helper()
	var fixtures []sliceFixture
	if err := json.Unmarshal(readFile(t, "../testdata/parity/slicing/cases.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func canonicalEntities(t testing.TB, raw []byte) string {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	var canonical func(any)
	canonical = func(v any) {
		switch v := v.(type) {
		case []any:
			for _, item := range v {
				canonical(item)
			}
			sort.Slice(v, func(i, j int) bool {
				a, _ := json.Marshal(v[i])
				b, _ := json.Marshal(v[j])
				return string(a) < string(b)
			})
		case map[string]any:
			for _, item := range v {
				canonical(item)
			}
		}
	}
	canonical(value)
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSliceEntitiesNativeParity(t *testing.T) {
	var expected []struct {
		Name     string
		Decision string
		Entities json.RawMessage
		Batches  [][]cedar.EntityUID
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/slicing/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	fixtures := sliceFixtures(t)
	if len(fixtures) != len(expected) {
		t.Fatal("regenerate slicing native fixtures")
	}
	for i, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			cfg, req := fixture.input()
			ctx := context.Background()
			rt := testRuntime(t)
			result, err := rt.SliceEntities(ctx, cfg, req)
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
			if canonicalEntities(t, gotEntities) != canonicalEntities(t, want.Entities) {
				t.Fatalf("entity slice differs from native\ngot %s\nwant %s", gotEntities, want.Entities)
			}
			for name, entities := range map[string]cedar.Entities{"full": cfg.Entities, "slice": result.Entities} {
				a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &cfg.Schema, Policies: cfg.Policies, Entities: entities})
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
	rt := testRuntime(t)
	fixtures := sliceFixtures(t)
	cases := []struct {
		name string
		edit func(*cedar.SliceConfig, *cedar.Request)
		kind cedar.ErrorKind
	}{
		{"invalid schema", func(c *cedar.SliceConfig, _ *cedar.Request) { c.Schema = cedar.SchemaFromCedar("invalid") }, cedar.KindSchema},
		{"invalid policies", func(c *cedar.SliceConfig, _ *cedar.Request) { c.Policies = cedar.PoliciesFromCedar("invalid") }, cedar.KindPolicies},
		{"unvalidated policy", func(c *cedar.SliceConfig, _ *cedar.Request) {
			c.Policies = cedar.PoliciesFromCedar(`permit(principal, action, resource) when { principal.profile.active == 1 };`)
		}, cedar.KindSlicing},
		{"invalid entity", func(c *cedar.SliceConfig, _ *cedar.Request) {
			c.Entities = cedar.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"bad"},"attrs":{},"parents":[]}]`))
		}, cedar.KindEntities},
		{"invalid JSON", func(c *cedar.SliceConfig, _ *cedar.Request) { c.Entities = cedar.EntitiesFromJSON([]byte(`[`)) }, cedar.KindInput},
		{"invalid UID", func(_ *cedar.SliceConfig, r *cedar.Request) { r.Principal.Type = "!!!" }, cedar.KindPrincipal},
		{"invalid context", func(_ *cedar.SliceConfig, r *cedar.Request) {
			r.Context = cedar.NewContext(cedar.Record{"bypass": cedar.Long(1)})
		}, cedar.KindRequest},
		{"context is not a record", func(_ *cedar.SliceConfig, r *cedar.Request) {
			r.Context = cedar.ContextFromJSON([]byte(`[]`))
		}, cedar.KindContext},
		{"invalid request", func(_ *cedar.SliceConfig, r *cedar.Request) { r.Principal = cedar.NewEntityUID("Doc", "report") }, cedar.KindRequest},
		{"iteration exhaustion", func(c *cedar.SliceConfig, _ *cedar.Request) { c.MaxIterations = 1 }, cedar.KindSlicing},
		{"conflicting entity", func(_ *cedar.SliceConfig, r *cedar.Request) {
			r.Entities = cedar.NewEntities(cedar.Entity{UID: cedar.NewEntityUID("User", "alice"), Attrs: cedar.Record{"profile": cedar.Record{"active": cedar.Bool(false), "label": cedar.String("conflict")}}})
		}, cedar.KindEntities},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg, req := fixtures[1].input()
			test.edit(&cfg, &req)
			result, err := rt.SliceEntities(context.Background(), cfg, req)
			var ce *cedar.Error
			if !errors.As(err, &ce) || ce.Kind != test.kind || result.Decision != cedar.Deny || !result.Entities.IsZero() || len(result.Batches) != 0 {
				t.Fatalf("expected %s with empty denying result, got %+v / %v", test.kind, result, err)
			}
		})
	}
	// A successful call after failures must not inherit any previous loader state.
	cfg, req := fixtures[0].input()
	if _, err := rt.SliceEntities(context.Background(), cfg, req); err != nil {
		t.Fatal(err)
	}
}

func TestSliceEntitiesCancellation(t *testing.T) {
	rt := testRuntime(t)
	cfg, req := sliceFixtures(t)[0].input()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := rt.SliceEntities(ctx, cfg, req)
	if !errors.Is(err, context.Canceled) || result.Decision != cedar.Deny {
		t.Fatalf("canceled call: %+v, %v", result, err)
	}
	cfg.Policies = cedar.PoliciesFromCedar(strings.Repeat(`permit(principal, action, resource) when { principal.profile.active };`, 10000))
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result, err = rt.SliceEntities(ctx, cfg, req)
	if !errors.Is(err, context.DeadlineExceeded) || result.Decision != cedar.Deny {
		t.Fatalf("deadline: %+v, %v", result, err)
	}
	cfg, req = sliceFixtures(t)[0].input()
	if _, err := rt.SliceEntities(context.Background(), cfg, req); err != nil {
		t.Fatal(err)
	}
}

func TestSliceEntitiesRequestData(t *testing.T) {
	cfg, req := sliceFixtures(t)[1].input()
	req.Entities, cfg.Entities = cfg.Entities, cedar.NewEntities()
	result, err := testRuntime(t).SliceEntities(context.Background(), cfg, req)
	if err != nil || result.Decision != cedar.Allow || len(result.Batches) < 2 {
		t.Fatalf("request-specific entities: %+v, %v", result, err)
	}
}

func TestSliceEntitiesLastIteration(t *testing.T) {
	cfg, req := sliceFixtures(t)[1].input()
	rt := testRuntime(t)
	result, err := rt.SliceEntities(context.Background(), cfg, req)
	if err != nil || len(result.Batches) < 2 {
		t.Fatalf("expected a relationship chain: %+v, %v", result, err)
	}
	cfg.MaxIterations = uint32(len(result.Batches))
	exact, err := rt.SliceEntities(context.Background(), cfg, req)
	if err != nil || exact.Decision != result.Decision {
		t.Fatalf("decision on final iteration: %+v, %v", exact, err)
	}
	cfg.MaxIterations--
	limited, err := rt.SliceEntities(context.Background(), cfg, req)
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindSlicing || limited.Decision != cedar.Deny {
		t.Fatalf("insufficient iterations: %+v, %v", limited, err)
	}
}

func TestSliceEntitiesConcurrent(t *testing.T) {
	rt := testRuntime(t)
	fixtures := sliceFixtures(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			cfg, req := fixtures[i%len(fixtures)].input()
			result, err := rt.SliceEntities(context.Background(), cfg, req)
			want := cedar.Allow
			if fixtures[i].Name == "optional_absent" {
				want = cedar.Deny
			}
			if err != nil || result.Decision != want {
				t.Errorf("concurrent request %d: %+v, %v", i, result, err)
			}
		})
	}
	wg.Wait()
}

func ExampleRuntime_SliceEntities() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		panic(err)
	}
	defer rt.Close(ctx)
	schema := cedar.SchemaFromCedar(`entity User; entity Photo { public: Bool }; action view appliesTo { principal: User, resource: Photo };`)
	policies := cedar.PoliciesFromCedar(`permit(principal, action, resource) when { resource.public };`)
	req := cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "beach")}
	slice, err := rt.SliceEntities(ctx, cedar.SliceConfig{
		Schema: schema, Policies: policies,
		Entities: cedar.NewEntities(
			cedar.Entity{UID: req.Resource, Attrs: cedar.Record{"public": cedar.Bool(true)}},
			cedar.Entity{UID: cedar.NewEntityUID("Photo", "unused"), Attrs: cedar.Record{"public": cedar.Bool(false)}},
		),
	}, req)
	if err != nil {
		panic(err)
	}
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: policies, Entities: slice.Entities})
	if err != nil {
		panic(err)
	}
	defer a.Close()
	response, err := a.Authorize(ctx, req)
	if err != nil {
		panic(err)
	}
	fmt.Println(slice.Decision, response.Decision, len(slice.Batches))
	// Output: allow allow 1
}
