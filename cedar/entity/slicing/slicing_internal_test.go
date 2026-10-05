package slicing

import (
	context "context"
	json "encoding/json"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	strings "strings"
	testing "testing"
)

func SlicingInput() (SliceConfig, cedarrequest.Request) {
	return SliceConfig{
		Schema:   cedarschema.SchemaFromCedar(`entity User; entity Photo { public: Bool, note: String }; action view appliesTo { principal: User, resource: Photo };`),
		Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { resource.public };`),
		Entities: cedarentity.NewEntities(cedarentity.Entity{UID: entityuid.NewEntityUID("Photo", "p"), Attrs: cedarvalue.Record{"public": cedarvalue.Bool(true), "note": cedarvalue.String("small")}}),
	}, cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "p")}
}

func TestSliceResourceLimits(t *testing.T) {
	ctx := context.Background()
	cfg, req := SlicingInput()
	in, err := json.Marshal(SliceInput{Schema: cfg.Schema.Wire(), Policies: cfg.Policies.Wire(), Entities: cfg.Entities,
		Request: cedarrequest.AuthorizeInput{Principal: req.Principal.Wire(), Action: req.Action.Wire(), Resource: req.Resource.Wire(), Context: req.Context}, MaxIterations: DefaultSliceIterations})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{len(in) - 1, len(in)} {
		rt, err := newRuntime(ctx, execution.WithMaxSourceBytes(limit))
		if err != nil {
			t.Fatal(err)
		}
		result, err := rt.SliceEntities(ctx, cfg, req)
		rt.runtime.Close(ctx)
		if limit == len(in) {
			if err != nil || result.Decision != cedarrequest.Allow {
				t.Fatalf("exact input limit: %+v, %v", result, err)
			}
		} else {
			var ce *diagnostic.Error
			if !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit || result.Decision != cedarrequest.Deny {
				t.Fatalf("input limit: %+v, %v", result, err)
			}
		}
	}
	rt, err := newRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(ctx)
	large := cfg
	large.Entities = cedarentity.NewEntities(cedarentity.Entity{UID: req.Resource, Attrs: cedarvalue.Record{"public": cedarvalue.Bool(true), "note": cedarvalue.String(strings.Repeat("x", 4<<20))}})
	rt.runtime.MaxSourceBytes = 1024
	result, err := rt.SliceEntities(ctx, large, req)
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit || result.Decision != cedarrequest.Deny || !result.Entities.IsZero() {
		t.Fatalf("source limit: %+v, %v", result, err)
	}
	rt.runtime.MaxSourceBytes = execution.DefaultMaxSourceBytes
	rt.runtime.MaxResponse = 32
	result, err = rt.SliceEntities(ctx, cfg, req)
	if !errors.Is(err, diagnostic.ErrFault) || result.Decision != cedarrequest.Deny || !result.Entities.IsZero() {
		t.Fatalf("output limit: %+v, %v", result, err)
	}
	rt.runtime.MaxResponse = execution.DefaultMaxResponseBytes
	result, err = rt.SliceEntities(ctx, cfg, req)
	if err != nil || result.Decision != cedarrequest.Allow {
		t.Fatalf("after faults: %+v, %v", result, err)
	}
	rt.runtime.Close(ctx)
	result, err = rt.SliceEntities(ctx, cfg, req)
	if err == nil || result.Decision != cedarrequest.Deny {
		t.Fatalf("closed runtime: %+v, %v", result, err)
	}
}

func TestDecodeSliceFailClosed(t *testing.T) {
	for _, response := range []string{
		`{`, `{}`, `{"decision":"maybe","entities":[],"batches":[]}`,
		`{"decision":"allow","batches":[]}`, `{"decision":"allow","entities":null,"batches":[]}`,
		`{"decision":"allow","entities":{},"batches":[]}`, `{"decision":"allow","entities":[]}`,
		`{"decision":"allow","error":{"kind":"future_kind","message":"unknown"}}`,
	} {
		result, err := DecodeSlice([]byte(response))
		if !errors.Is(err, diagnostic.ErrFault) || result.Decision != cedarrequest.Deny || !result.Entities.IsZero() {
			t.Fatalf("%s: %+v, %v", response, result, err)
		}
	}
}
