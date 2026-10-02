package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// Upstream chooses the "did you mean" hint by hash iteration, so the suggested
// type varies between identical runs; it is excluded from the determinism claim.
var propHelpHint = regexp.MustCompile("(help: did you mean `[^`]*`\\?)")

func propStripHints(messages []cedar.PolicyMessage) []cedar.PolicyMessage {
	out := slices.Clone(messages)
	for i := range out {
		out[i].Message = propHelpHint.ReplaceAllString(out[i].Message, "")
	}
	return out
}

// The API does not document diagnostic order, so compare as sorted multisets.
func propSortedMessages(messages []cedar.PolicyMessage) []cedar.PolicyMessage {
	out := slices.Clone(messages)
	slices.SortFunc(out, func(a, b cedar.PolicyMessage) int {
		if a.PolicyID != b.PolicyID {
			return strings.Compare(a.PolicyID, b.PolicyID)
		}
		return strings.Compare(a.Message, b.Message)
	})
	return out
}

func propSameValidation(t *rapid.T, a, b cedar.ValidationResult) {
	t.Helper()
	if a.Passed != b.Passed ||
		!slices.Equal(propSortedMessages(propStripHints(a.Errors)), propSortedMessages(propStripHints(b.Errors))) ||
		!slices.Equal(propSortedMessages(propStripHints(a.Warnings)), propSortedMessages(propStripHints(b.Warnings))) {
		t.Fatalf("validation is not deterministic: %+v vs %+v", a, b)
	}
}

// Validation of the same (schema, policies) pair always yields identical diagnostics.
func TestPropertyValidationDeterministic(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		policies := cedar.PoliciesFromCedar(propGenPolicySet(3).Draw(pt, "policies"))
		first, err := rt.Validate(ctx, d.schema, policies)
		if err != nil {
			pt.Fatalf("validate: %v", err)
		}
		second, err := rt.Validate(ctx, d.schema, policies)
		if err != nil {
			pt.Fatalf("second validate: %v", err)
		}
		propSameValidation(pt, first, second)
	})
}

// Sampled corpus tests validate deterministically, and tests the corpus says
// should validate never produce validation errors under their own schema.
func TestPropertyCorpusValidationStable(t *testing.T) {
	dir := os.Getenv("CEDAR_CORPUS_DIR")
	if dir == "" {
		t.Skip("CEDAR_CORPUS_DIR is not set; see CONTRIBUTING.md")
	}
	files, err := filepath.Glob(filepath.Join(dir, "corpus-tests", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus tests in %s: %v", dir, err)
	}
	files = slices.DeleteFunc(files, func(f string) bool { return strings.HasSuffix(f, ".entities.json") })
	// Large fixtures have high validation costs; sample the remaining fixtures.
	files = slices.DeleteFunc(files, func(f string) bool {
		info, err := os.Stat(f)
		return err != nil || info.Size() > 128<<10
	})
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		file := rapid.SampledFrom(files).Draw(pt, "file")
		raw, err := os.ReadFile(file)
		if err != nil {
			pt.Fatalf("read: %v", err)
		}
		var tt corpusTest
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&tt); err != nil {
			pt.Fatalf("decode: %v", err)
		}
		read := func(rel string) []byte {
			b, err := os.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				pt.Fatalf("read %s: %v", rel, err)
			}
			return b
		}
		schema := parseSchema(tt.SchemaFormat, string(read(tt.Schema)))
		policies := parsePolicies(tt.PolicyFormat, string(read(tt.Policies)))
		first, err := rt.Validate(ctx, schema, policies)
		if err != nil {
			pt.Fatalf("validate: %v", err)
		}
		second, err := rt.Validate(ctx, schema, policies)
		if err != nil {
			pt.Fatalf("second validate: %v", err)
		}
		propSameValidation(pt, first, second)
		if tt.ShouldValidate && !first.Passed {
			pt.Fatalf("%s: corpus expects validation to pass: %+v", filepath.Base(file), first.Errors)
		}
	})
}
