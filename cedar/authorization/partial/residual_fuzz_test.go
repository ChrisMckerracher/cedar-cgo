package partial_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	partialfixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/partial"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func FuzzResidualImport(f *testing.F) {
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(partialfixture.PartialSchema)
	a, err := testruntime.New(f).NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa || 9223372036854775807 + 1 > 0 };`)})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { a.Close() })
	partial, err := a.Partial().PartialAuthorize(ctx, partialfixture.PartialRequest())
	if err != nil {
		f.Fatal(err)
	}
	seed, err := partial.Export()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(seed))
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`{"version":1,"cedar_version":"4.13.0","partial":{},"projection":{}}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		got, err := a.Partial().ImportPartialResponse(ctx, []byte(input))
		if err != nil {
			var ce *diagnostic.Error
			if got.Decision != cedarpartial.Undecided || !errors.As(err, &ce) {
				t.Fatalf("import error: %+v %v", got, err)
			}
			return
		}
		exported, err := got.Export()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Partial().ImportPartialResponse(ctx, exported); err != nil {
			t.Fatalf("accepted export cannot be imported: %v", err)
		}
	})
}
