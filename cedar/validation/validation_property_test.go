package validation_test

import (
	corpus "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/corpus"
	generator "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/generator"
	joy "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"

	bytes "bytes"
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"

	os "os"
	filepath "path/filepath"
	rapid "pgregory.net/rapid"
	slices "slices"
	strings "strings"
	testing "testing"
)

// Validation of the same (schema, policies) pair always yields identical diagnostics.
func TestPropertyValidationDeterministic(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		policies := cedarpolicy.PoliciesFromCedar(generator.PropGenPolicySet(3).Draw(pt, "policies"))
		first, err := rt.Validation().Validate(ctx, d.Schema, policies)
		if err != nil {
			pt.Fatalf("validate: %v", err)
		}
		second, err := rt.Validation().Validate(ctx, d.Schema, policies)
		if err != nil {
			pt.Fatalf("second validate: %v", err)
		}
		generator.PropSameValidation(pt, first, second)
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
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		file := rapid.SampledFrom(files).Draw(pt, "file")
		raw, err := fixture.ReadFile(file)
		if err != nil {
			pt.Fatalf("read: %v", err)
		}
		var tt corpus.CorpusTest
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&tt); err != nil {
			pt.Fatalf("decode: %v", err)
		}
		read := func(rel string) []byte {
			b, err := fixture.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				pt.Fatalf("read %s: %v", rel, err)
			}
			return b
		}
		schema := corpus.ParseSchema(tt.SchemaFormat, string(read(tt.Schema)))
		policies := corpus.ParsePolicies(tt.PolicyFormat, string(read(tt.Policies)))
		first, err := rt.Validation().Validate(ctx, schema, policies)
		if err != nil {
			pt.Fatalf("validate: %v", err)
		}
		second, err := rt.Validation().Validate(ctx, schema, policies)
		if err != nil {
			pt.Fatalf("second validate: %v", err)
		}
		generator.PropSameValidation(pt, first, second)
		if tt.ShouldValidate && !first.Passed {
			pt.Fatalf("%s: corpus expects validation to pass: %+v", filepath.Base(file), first.Errors)
		}
	})
}
