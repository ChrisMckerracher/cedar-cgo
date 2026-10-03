package cedar_test

import (
	"context"
	"errors"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzResidualImport(f *testing.F) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(partialSchema)
	a, err := testRuntime(f).NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa || 9223372036854775807 + 1 > 0 };`)})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { a.Close() })
	partial, err := a.PartialAuthorize(ctx, partialRequest())
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
		got, err := a.ImportPartialResponse(ctx, []byte(input))
		if err != nil {
			var ce *cedar.Error
			if got.Decision != cedar.Undecided || !errors.As(err, &ce) {
				t.Fatalf("import error: %+v %v", got, err)
			}
			return
		}
		exported, err := got.Export()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.ImportPartialResponse(ctx, exported); err != nil {
			t.Fatalf("accepted export cannot be imported: %v", err)
		}
	})
}
