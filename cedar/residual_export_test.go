package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestResidualProjectionPreservesNestedErrors(t *testing.T) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(partialSchema)
	rt := testRuntime(t)
	policies := cedar.PoliciesFromCedar(`@note("雪") permit(principal, action, resource) when { context.mfa || 9223372036854775807 + 1 > 0 };`)
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r, err := a.PartialAuthorize(ctx, partialRequest())
	if err != nil || r.Decision != cedar.Undecided || r.Residuals[0].State != cedar.ResidualUnknown {
		t.Fatalf("partial: %+v %v", r, err)
	}
	projection := r.Projection()
	if projection.Version != cedar.ResidualProjectionVersion || projection.CedarVersion != cedar.CedarVersion || !bytes.Contains(projection.Policies["policy0"], []byte(`"error":[]`)) {
		t.Fatalf("nested error missing: %+v", projection)
	}
	before, err := r.Export()
	if err != nil {
		t.Fatal(err)
	}
	projection.Policies["policy0"][0] = '!'
	r.Residuals[0].Cedar = "edited"
	r.Residuals[0].State = cedar.ResidualTrue
	r.Decision = cedar.PartialAllow
	after, err := r.Export()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection changed export")
	}
	second, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	imported, err := second.ImportPartialResponse(ctx, before)
	if err != nil {
		t.Fatal(err)
	}
	for _, mfa := range []bool{true, false} {
		req := simpleRequest(cedar.NewContext(cedar.Record{"mfa": cedar.Bool(mfa)}))
		got, err := imported.Reauthorize(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		native, err := r.Reauthorize(ctx, req)
		if err != nil || !propResponseEqual(got, native) {
			t.Fatalf("imported replay: %+v; native residual: %+v %v", got, native, err)
		}
		want, err := second.Authorize(ctx, req)
		if err != nil || got.Decision != want.Decision || !reflect.DeepEqual(got.Reasons, want.Reasons) || len(got.Errors) != len(want.Errors) {
			t.Fatalf("imported replay: %+v; direct: %+v %v", got, want, err)
		}
		for i, evaluation := range got.Errors {
			if evaluation.PolicyID != want.Errors[i].PolicyID || evaluation.Message == "" {
				t.Fatalf("imported error: %+v; direct error: %+v", evaluation, want.Errors[i])
			}
		}
	}
}

func TestResidualImportRejectsEditedExports(t *testing.T) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(partialSchema)
	a, err := testRuntime(t).NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa };`)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	partial, err := a.PartialAuthorize(ctx, partialRequest())
	if err != nil {
		t.Fatal(err)
	}
	data, err := partial.Export()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(e map[string]any) { e["version"] = float64(2) },
		func(e map[string]any) { e["cedar_version"] = "0.0.0" },
		func(e map[string]any) { e["extra"] = true },
		func(e map[string]any) { e["projection"].(map[string]any)["version"] = float64(2) },
		func(e map[string]any) { e["projection"].(map[string]any)["cedar_version"] = "0.0.0" },
		func(e map[string]any) {
			delete(e["projection"].(map[string]any)["policies"].(map[string]any), "policy0")
		},
		func(e map[string]any) {
			e["projection"].(map[string]any)["policies"].(map[string]any)["policy0"].(map[string]any)["effect"] = "forbid"
		},
		func(e map[string]any) {
			e["projection"].(map[string]any)["policies"].(map[string]any)["policy0"].(map[string]any)["conditions"] = []any{}
		},
	} {
		var envelope map[string]any
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		change(envelope)
		changed, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		got, err := a.ImportPartialResponse(ctx, changed)
		var ce *cedar.Error
		if got.Decision != cedar.Undecided || !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
			t.Fatalf("edited export accepted: %+v %v", got, err)
		}
	}
	other, err := testRuntime(t).NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(`forbid(principal, action, resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	_, err = other.ImportPartialResponse(ctx, data)
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
		t.Fatalf("different policy set accepted: %v", err)
	}
	projection := partial.Projection()
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	var decoded cedar.ResidualProjection
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(projection, decoded) {
		t.Fatalf("projection serialization: %+v %v", decoded, err)
	}
}

func TestResidualRawPolicyIDs(t *testing.T) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(partialSchema)
	for _, id := range []string{"", "policy\"\n\\\x00"} {
		a, err := testRuntime(t).NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: partialIDPolicies(t, map[string]json.RawMessage{
			id: partialIDPolicy("permit", "when", `{".":{"left":{"Var":"context"},"attr":"mfa"}}`),
		})})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close() })
		partial, err := a.PartialAuthorize(ctx, partialRequest())
		if err != nil || partial.Decision != cedar.Undecided || len(partial.Residuals) != 1 || partial.Residuals[0].PolicyID != id {
			t.Fatalf("partial policy ID %q: %+v %v", id, partial, err)
		}
		if _, exists := partial.Projection().Policies[id]; !exists {
			t.Fatalf("projection lost policy ID %q", id)
		}
		data, err := partial.Export()
		if err != nil {
			t.Fatal(err)
		}
		imported, err := a.ImportPartialResponse(ctx, data)
		if err != nil || len(imported.Residuals) != 1 || imported.Residuals[0].PolicyID != id {
			t.Fatalf("imported policy ID %q: %+v %v", id, imported, err)
		}
		for _, mfa := range []bool{true, false} {
			req := simpleRequest(cedar.NewContext(cedar.Record{"mfa": cedar.Bool(mfa)}))
			got, err := imported.Reauthorize(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			want, err := a.Authorize(ctx, req)
			if err != nil || !propResponseEqual(got, want) {
				t.Fatalf("replay policy ID %q: %+v; direct: %+v %v", id, got, want, err)
			}
			if mfa && (len(got.Reasons) != 1 || got.Reasons[0] != id) {
				t.Fatalf("replay lost policy ID %q: %+v", id, got)
			}
		}
	}
}
