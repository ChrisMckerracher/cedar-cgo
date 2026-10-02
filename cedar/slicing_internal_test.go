package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
)

func slicingInput() (SliceConfig, Request) {
	return SliceConfig{
		Schema:   SchemaFromCedar(`entity User; entity Photo { public: Bool, note: String }; action view appliesTo { principal: User, resource: Photo };`),
		Policies: PoliciesFromCedar(`permit(principal, action, resource) when { resource.public };`),
		Entities: NewEntities(Entity{UID: NewEntityUID("Photo", "p"), Attrs: Record{"public": Bool(true), "note": String("small")}}),
	}, Request{Principal: NewEntityUID("User", "alice"), Action: NewEntityUID("Action", "view"), Resource: NewEntityUID("Photo", "p")}
}

func TestSliceResourceLimits(t *testing.T) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	defer cache.Close(ctx)
	cfg, req := slicingInput()
	in, err := json.Marshal(sliceInput{Schema: cfg.Schema.wire(), Policies: cfg.Policies.wire(), Entities: cfg.Entities,
		Request: authorizeInput{Principal: req.Principal.wire(), Action: req.Action.wire(), Resource: req.Resource.wire(), Context: req.Context}, MaxIterations: DefaultSliceIterations})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{len(in) - 1, len(in)} {
		rt, err := NewRuntime(ctx, WithCompilationCache(cache), WithMaxSourceBytes(limit))
		if err != nil {
			t.Fatal(err)
		}
		result, err := rt.SliceEntities(ctx, cfg, req)
		rt.Close(ctx)
		if limit == len(in) {
			if err != nil || result.Decision != Allow {
				t.Fatalf("exact input limit: %+v, %v", result, err)
			}
		} else {
			var ce *Error
			if !errors.As(err, &ce) || ce.Kind != KindLimit || result.Decision != Deny {
				t.Fatalf("input limit: %+v, %v", result, err)
			}
		}
	}
	rt, err := NewRuntime(ctx, WithCompilationCache(cache), WithMemoryLimit(16<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	large := cfg
	large.Entities = NewEntities(Entity{UID: req.Resource, Attrs: Record{"public": Bool(true), "note": String(strings.Repeat("x", 4<<20))}})
	result, err := rt.SliceEntities(ctx, large, req)
	if !errors.Is(err, ErrFault) || result.Decision != Deny || !result.Entities.IsZero() {
		t.Fatalf("memory limit: %+v, %v", result, err)
	}
	rt.maxResponse = 32
	result, err = rt.SliceEntities(ctx, cfg, req)
	if !errors.Is(err, ErrFault) || result.Decision != Deny || !result.Entities.IsZero() {
		t.Fatalf("output limit: %+v, %v", result, err)
	}
	rt.maxResponse = DefaultMaxResponseBytes
	result, err = rt.SliceEntities(ctx, cfg, req)
	if err != nil || result.Decision != Allow {
		t.Fatalf("after faults: %+v, %v", result, err)
	}
	rt.Close(ctx)
	result, err = rt.SliceEntities(ctx, cfg, req)
	if err == nil || result.Decision != Deny {
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
		result, err := decodeSlice([]byte(response))
		if !errors.Is(err, ErrFault) || result.Decision != Deny || !result.Entities.IsZero() {
			t.Fatalf("%s: %+v, %v", response, result, err)
		}
	}
}
