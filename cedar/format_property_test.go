package cedar_test

import (
	"context"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// Formatting is idempotent and its output re-parses (docs/verification.md,
// "Formatting parity"), for any layout options within the documented ranges.
func TestPropertyFormatIdempotent(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		text := propGenPolicySet(3).Draw(pt, "policies")
		opts := []cedar.FormatOption{
			cedar.WithFormatLineWidth(rapid.Uint32Range(0, 120).Draw(pt, "width")),
			cedar.WithFormatIndentWidth(rapid.Int32Range(0, 8).Draw(pt, "indent")),
		}
		formatted, err := rt.FormatPolicies(ctx, text, opts...)
		if err != nil {
			pt.Fatalf("grammar output rejected by formatter: %v\n%s", err, text)
		}
		again, err := rt.FormatPolicies(ctx, formatted, opts...)
		if err != nil || again != formatted {
			pt.Fatalf("formatting is not idempotent: %q, %v", again, err)
		}
		// Re-parsing only: an empty schema reports type errors, not parse errors.
		if _, err := rt.Validate(ctx, cedar.SchemaFromCedar(""), cedar.PoliciesFromCedar(formatted)); err != nil {
			pt.Fatalf("formatted output does not re-parse: %v\n%s", err, formatted)
		}
	})
}

// Concrete authorization results are identical before and after formatting.
func TestPropertyFormatPreservesAuthorization(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		text := propGenPolicySet(2).Draw(pt, "policies")
		formatted, err := rt.FormatPolicies(ctx, text)
		if err != nil {
			pt.Fatalf("grammar output rejected by formatter: %v\n%s", err, text)
		}
		req := propGenRequest().Draw(pt, "request")
		authorize := func(source string) cedar.Response {
			a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: cedar.PoliciesFromCedar(source), Entities: d.entities})
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
		if before, after := authorize(text), authorize(formatted); !propResponseEqual(before, after) {
			pt.Fatalf("formatting changed authorization: %+v vs %+v\n%s", before, after, text)
		}
	})
}
