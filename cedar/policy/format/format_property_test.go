package format_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"
	joy "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	policyformat "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/format"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Formatting is idempotent and its output re-parses (docs/verification.md,
// "Formatting parity"), for any layout options within the documented ranges.
func TestPropertyFormatIdempotent(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		TextValue := generator.PropGenPolicySet(3).Draw(pt, "policies")
		opts := []policyformat.FormatOption{
			policyformat.WithFormatLineWidth(rapid.Uint32Range(0, 120).Draw(pt, "width")),
			policyformat.WithFormatIndentWidth(rapid.Int32Range(0, 8).Draw(pt, "indent")),
		}
		formatted, err := rt.Formatter().FormatPolicies(ctx, TextValue, opts...)
		if err != nil {
			pt.Fatalf("grammar output rejected by formatter: %v\n%s", err, TextValue)
		}
		again, err := rt.Formatter().FormatPolicies(ctx, formatted, opts...)
		if err != nil || again != formatted {
			pt.Fatalf("formatting is not idempotent: %q, %v", again, err)
		}
		// Re-parsing only: an empty schema reports type errors, not parse errors.
		if _, err := rt.Validation().Validate(ctx, cedarschema.SchemaFromCedar(""), cedarpolicy.PoliciesFromCedar(formatted)); err != nil {
			pt.Fatalf("formatted output does not re-parse: %v\n%s", err, formatted)
		}
	})
}

// Concrete authorization results are identical before and after formatting.
func TestPropertyFormatPreservesAuthorization(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		TextValue := generator.PropGenPolicySet(2).Draw(pt, "policies")
		formatted, err := rt.Formatter().FormatPolicies(ctx, TextValue)
		if err != nil {
			pt.Fatalf("grammar output rejected by formatter: %v\n%s", err, TextValue)
		}
		req := generator.PropGenRequest().Draw(pt, "request")
		authorize := func(source string) cedarrequest.Response {
			a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &d.Schema, Policies: cedarpolicy.PoliciesFromCedar(source), Entities: d.Entities})
			if err != nil {
				pt.Fatalf("load: %v\n%s", err, source)
			}
			defer a.Close()
			resp, err := a.Authorize(ctx, req)
			if err != nil {
				pt.Fatalf("authorize: %v", err)
			}
			return resp
		}
		if before, after := authorize(TextValue), authorize(formatted); !generator.PropResponseEqual(before, after) {
			pt.Fatalf("formatting changed authorization: %+v vs %+v\n%s", before, after, TextValue)
		}
	})
}
