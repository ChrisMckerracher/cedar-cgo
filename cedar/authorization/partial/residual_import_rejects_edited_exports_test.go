package partial_test

import (
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"
	partialfixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/partial"
	policysupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/policy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"

	reflect "reflect"
	testing "testing"
)

func TestResidualImportRejectsEditedExports(t *testing.T) {
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(partialfixture.PartialSchema)
	a, err := testruntime.New(t).NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa };`)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	partial, err := a.Partial().PartialAuthorize(ctx, partialfixture.PartialRequest())
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
		got, err := a.Partial().ImportPartialResponse(ctx, changed)
		var ce *diagnostic.Error
		if got.Decision != cedarpartial.Undecided || !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
			t.Fatalf("edited export accepted: %+v %v", got, err)
		}
	}
	other, err := testruntime.New(t).NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`forbid(principal, action, resource);`)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	_, err = other.Partial().ImportPartialResponse(ctx, data)
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
		t.Fatalf("different policy set accepted: %v", err)
	}
	projection := partial.Projection()
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	var decoded cedarpartial.ResidualProjection
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(projection, decoded) {
		t.Fatalf("projection serialization: %+v %v", decoded, err)
	}
}

func TestResidualRawPolicyIDs(t *testing.T) {
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(partialfixture.PartialSchema)
	for _, id := range []string{"", "policy\"\n\\\x00"} {
		a, err := testruntime.New(t).NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policysupport.PartialIDPolicies(t, map[string]json.RawMessage{
			id: policysupport.PartialIDPolicy("permit", "when", `{".":{"left":{"Var":"context"},"attr":"mfa"}}`),
		})})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close() })
		partial, err := a.Partial().PartialAuthorize(ctx, partialfixture.PartialRequest())
		if err != nil || partial.Decision != cedarpartial.Undecided || len(partial.Residuals) != 1 || partial.Residuals[0].PolicyID != id {
			t.Fatalf("partial policy ID %q: %+v %v", id, partial, err)
		}
		if _, exists := partial.Projection().Policies[id]; !exists {
			t.Fatalf("projection lost policy ID %q", id)
		}
		data, err := partial.Export()
		if err != nil {
			t.Fatal(err)
		}
		imported, err := a.Partial().ImportPartialResponse(ctx, data)
		if err != nil || len(imported.Residuals) != 1 || imported.Residuals[0].PolicyID != id {
			t.Fatalf("imported policy ID %q: %+v %v", id, imported, err)
		}
		for _, mfa := range []bool{true, false} {
			req := fault.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(mfa)}))
			got, err := imported.Reauthorize(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			want, err := a.Authorize(ctx, req)
			if err != nil || !generator.PropResponseEqual(got, want) {
				t.Fatalf("replay policy ID %q: %+v; direct: %+v %v", id, got, want, err)
			}
			if mfa && (len(got.Reasons) != 1 || got.Reasons[0] != id) {
				t.Fatalf("replay lost policy ID %q: %+v", id, got)
			}
		}
	}
}
