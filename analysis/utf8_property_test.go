package analysis_test

import (
	"context"
	"errors"
	"testing"
	"unicode/utf8"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// propGenSource draws arbitrary valid-UTF-8 text; the rejection invariant
// below does not depend on the text being a well-formed policy or schema.
var propGenSource = rapid.StringOfN(rapid.Rune(), 0, 16, 128)

// propGenMalformedSource injects a never-valid byte at a drawn offset; the
// result is always invalid UTF-8 regardless of the surrounding bytes.
func propGenMalformedSource(t *rapid.T, text string) string {
	t.Helper()
	at := rapid.IntRange(0, len(text)).Draw(t, "at")
	never := byte(0xfe + rapid.IntRange(0, 1).Draw(t, "byte"))
	out := text[:at] + string([]byte{never}) + text[at:]
	if utf8.ValidString(out) {
		t.Fatalf("corruption produced valid UTF-8: %q", out)
	}
	return out
}

// Malformed UTF-8 in any analysis input is rejected before the solver runs;
// the zero analyzer has neither solver nor module, so passing this property
// proves the rejection happens at the Go boundary.
func TestPropertyMalformedUTF8AnalysisInputRejected(t *testing.T) {
	a := &analysis.Analyzer{}
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		bad := propGenMalformedSource(pt, propGenSource.Draw(pt, "text"))
		inputs := []struct {
			schema        cedar.Schema
			first, second cedar.PolicySet
		}{
			{schema: cedar.SchemaFromCedar(bad)},
			{schema: cedar.SchemaFromJSON([]byte(bad))},
			{first: cedar.PoliciesFromCedar(bad)},
			{second: cedar.PoliciesFromJSON([]byte(bad))},
		}
		for _, in := range inputs {
			_, err := a.Equivalent(ctx, in.schema, in.first, in.second)
			var e *analysis.Error
			if !errors.As(err, &e) || e.Kind != string(cedar.KindInput) {
				pt.Fatalf("Equivalent: got %v; want input error", err)
			}
			_, err = a.NewlyPermitted(ctx, in.schema, in.first, in.second)
			if !errors.As(err, &e) || e.Kind != string(cedar.KindInput) {
				pt.Fatalf("NewlyPermitted: got %v; want input error", err)
			}
		}
	})
}
