package utility_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	context "context"
	errors "errors"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"

	rapid "pgregory.net/rapid"
	reflect "reflect"
	testing "testing"
)

func TestPropertyConfusableDetection(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		// Variant A: pure-ASCII literals never mix scripts.
		base := rapid.StringMatching(`[a-z0-9 ]{0,16}`).Draw(pt, "ascii")
		warnings, err := rt.Utilities().ConfusableStrings(ctx, cedarpolicy.PoliciesFromCedar(
			fmt.Sprintf(`permit(principal, action, resource) when { %q == %q };`, base, base)))
		if err != nil || len(warnings) != 0 {
			pt.Fatalf("ASCII %q: %+v %v", base, warnings, err)
		}
		// Variant B: Cyrillic 'а' (U+0430) needs a Latin letter to mix with;
		// digits and spaces alone stay single-script, so the base must lead with one.
		mixedBase := rapid.StringMatching(`[a-z][a-z0-9 ]{0,15}`).Draw(pt, "mixedBase")
		pos := rapid.IntRange(0, len(mixedBase)).Draw(pt, "position")
		spliced := mixedBase[:pos] + "а" + mixedBase[pos:]
		policies := cedarpolicy.PoliciesFromCedar(
			fmt.Sprintf(`permit(principal, action, resource) when { %q == %q };`, spliced, mixedBase))
		warnings, err = rt.Utilities().ConfusableStrings(ctx, policies)
		if err != nil || len(warnings) == 0 {
			pt.Fatalf("mixed %q: %+v %v", spliced, warnings, err)
		}
		for _, warning := range warnings {
			if warning.Category != "mixed_script_string" || warning.Severity != diagnostic.SeverityWarning {
				pt.Fatalf("mixed %q: unexpected warning %+v", spliced, warning)
			}
		}
		// Variant C: detection is deterministic, spans included.
		again, err := rt.Utilities().ConfusableStrings(ctx, policies)
		if err != nil || !reflect.DeepEqual(again, warnings) {
			pt.Fatalf("unstable warnings for %q: %+v vs %+v %v", spliced, warnings, again, err)
		}
	})
}

func TestPropertyScopeValidation(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(generator.PropUtilSchema)
	rapid.Check(t, func(pt *rapid.T) {
		principalType := rapid.SampledFrom([]string{"User", "Photo"}).Draw(pt, "principalType")
		resourceType := rapid.SampledFrom([]string{"User", "Photo"}).Draw(pt, "resourceType")
		actionID := rapid.SampledFrom([]string{"view", "edit"}).Draw(pt, "actionID")
		wireType := principalType
		if rapid.Bool().Draw(pt, "invalidUTF8") {
			wireType = "\xff"
		}
		err := rt.Utilities().ValidateScopeVariables(ctx, schema,
			entityuid.NewEntityUID(wireType, "x"), entityuid.NewEntityUID("Action", actionID), entityuid.NewEntityUID(resourceType, "p"))
		var ce *diagnostic.Error
		if wireType != principalType {
			if !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
				pt.Fatalf("invalid UTF-8 type accepted: %v", err)
			}
			return
		}
		// Well-formed scope UIDs only ever miss the declared request environment.
		fits := principalType == "User" && actionID == "view" && resourceType == "Photo"
		if fits != (err == nil) || (!fits && (!errors.As(err, &ce) || ce.Kind != diagnostic.KindRequest)) {
			pt.Fatalf("scope %q/%q/%q: %v", principalType, actionID, resourceType, err)
		}
	})
}
