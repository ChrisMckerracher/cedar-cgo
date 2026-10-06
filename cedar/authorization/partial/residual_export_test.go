package partial_test

import (
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"
	partialfixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/partial"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	bytes "bytes"
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"

	reflect "reflect"
	testing "testing"
)

func TestResidualProjectionPreservesNestedErrors(t *testing.T) {
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(partialfixture.PartialSchema)
	rt := testruntime.New(t)
	policies := cedarpolicy.PoliciesFromCedar(`@note("雪") permit(principal, action, resource) when { context.mfa || 9223372036854775807 + 1 > 0 };`)
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r, err := a.Partial().PartialAuthorize(ctx, partialfixture.PartialRequest())
	if err != nil || r.Decision != cedarpartial.Undecided || r.Residuals[0].State != cedarpartial.ResidualUnknown {
		t.Fatalf("partial: %+v %v", r, err)
	}
	projection := r.Projection()
	if projection.Version != cedarpartial.ResidualProjectionVersion || projection.CedarVersion != syntax.CedarVersion || !bytes.Contains(projection.Policies["policy0"], []byte(`"error":[]`)) {
		t.Fatalf("nested error missing: %+v", projection)
	}
	before, err := r.Export()
	if err != nil {
		t.Fatal(err)
	}
	projection.Policies["policy0"][0] = '!'
	r.Residuals[0].Cedar = "edited"
	r.Residuals[0].State = cedarpartial.ResidualTrue
	r.Decision = cedarpartial.PartialAllow
	after, err := r.Export()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection changed export")
	}
	second, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	imported, err := second.Partial().ImportPartialResponse(ctx, before)
	if err != nil {
		t.Fatal(err)
	}
	for _, mfa := range []bool{true, false} {
		req := fault.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(mfa)}))
		got, err := imported.Reauthorize(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		native, err := r.Reauthorize(ctx, req)
		if err != nil || !generator.PropResponseEqual(got, native) {
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
