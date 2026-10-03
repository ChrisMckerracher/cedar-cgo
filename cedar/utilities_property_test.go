package cedar_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// propUtilSchema declares exactly one fitting scope triple: User / Action::"view" / Photo.
const propUtilSchema = `entity User; entity Photo; action "view" appliesTo { principal: User, resource: Photo, context: {} };`

// propUtilGenScalar draws the Cedar leaf values whose evaluated shape the merge
// oracle can rebuild exactly: Bool, Long, and String.
func propUtilGenScalar() *rapid.Generator[cedar.Value] {
	return rapid.OneOf(
		rapid.Map(rapid.Bool(), func(b bool) cedar.Value { return cedar.Bool(b) }),
		rapid.Map(rapid.Int64(), func(n int64) cedar.Value { return cedar.Long(n) }),
		rapid.Map(rapid.StringN(0, 8, 32), func(s string) cedar.Value { return cedar.String(s) }),
	)
}

// propUtilEvalOf narrows a drawn scalar to its evaluated shape; Bool, Long, and
// String are their own EvalResult variants.
func propUtilEvalOf(value cedar.Value) cedar.EvalResult {
	switch scalar := value.(type) {
	case cedar.Bool:
		return scalar
	case cedar.Long:
		return scalar
	default:
		return scalar.(cedar.String)
	}
}

func TestPropertyConfusableDetection(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		// Variant A: pure-ASCII literals never mix scripts.
		base := rapid.StringMatching(`[a-z0-9 ]{0,16}`).Draw(pt, "ascii")
		warnings, err := rt.ConfusableStrings(ctx, cedar.PoliciesFromCedar(
			fmt.Sprintf(`permit(principal, action, resource) when { %q == %q };`, base, base)))
		if err != nil || len(warnings) != 0 {
			pt.Fatalf("ASCII %q: %+v %v", base, warnings, err)
		}
		// Variant B: Cyrillic 'а' (U+0430) needs a Latin letter to mix with;
		// digits and spaces alone stay single-script, so the base must lead with one.
		mixedBase := rapid.StringMatching(`[a-z][a-z0-9 ]{0,15}`).Draw(pt, "mixedBase")
		pos := rapid.IntRange(0, len(mixedBase)).Draw(pt, "position")
		spliced := mixedBase[:pos] + "а" + mixedBase[pos:]
		policies := cedar.PoliciesFromCedar(
			fmt.Sprintf(`permit(principal, action, resource) when { %q == %q };`, spliced, mixedBase))
		warnings, err = rt.ConfusableStrings(ctx, policies)
		if err != nil || len(warnings) == 0 {
			pt.Fatalf("mixed %q: %+v %v", spliced, warnings, err)
		}
		for _, warning := range warnings {
			if warning.Category != "mixed_script_string" || warning.Severity != cedar.SeverityWarning {
				pt.Fatalf("mixed %q: unexpected warning %+v", spliced, warning)
			}
		}
		// Variant C: detection is deterministic, spans included.
		again, err := rt.ConfusableStrings(ctx, policies)
		if err != nil || !reflect.DeepEqual(again, warnings) {
			pt.Fatalf("unstable warnings for %q: %+v vs %+v %v", spliced, warnings, again, err)
		}
	})
}

func TestPropertyScopeValidation(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(propUtilSchema)
	rapid.Check(t, func(pt *rapid.T) {
		principalType := rapid.SampledFrom([]string{"User", "Photo"}).Draw(pt, "principalType")
		resourceType := rapid.SampledFrom([]string{"User", "Photo"}).Draw(pt, "resourceType")
		actionID := rapid.SampledFrom([]string{"view", "edit"}).Draw(pt, "actionID")
		wireType := principalType
		if rapid.Bool().Draw(pt, "invalidUTF8") {
			wireType = "\xff"
		}
		err := rt.ValidateScopeVariables(ctx, schema,
			cedar.NewEntityUID(wireType, "x"), cedar.NewEntityUID("Action", actionID), cedar.NewEntityUID(resourceType, "p"))
		var ce *cedar.Error
		if wireType != principalType {
			if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
				pt.Fatalf("invalid UTF-8 type accepted: %v", err)
			}
			return
		}
		// Well-formed scope UIDs only ever miss the declared request environment.
		fits := principalType == "User" && actionID == "view" && resourceType == "Photo"
		if fits != (err == nil) || (!fits && (!errors.As(err, &ce) || ce.Kind != cedar.KindRequest)) {
			pt.Fatalf("scope %q/%q/%q: %v", principalType, actionID, resourceType, err)
		}
	})
}

func TestPropertyContextMergeDisjointKeys(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	keys := []string{"a", "b", "c", "d"}
	rapid.Check(t, func(pt *rapid.T) {
		leftKeys := rapid.SliceOfNDistinct(rapid.SampledFrom(keys), 0, 4, func(k string) string { return k }).Draw(pt, "leftKeys")
		rest := slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return slices.Contains(leftKeys, k) })
		var rightKeys []string
		if len(rest) > 0 {
			rightKeys = rapid.SliceOfNDistinct(rapid.SampledFrom(rest), 0, len(rest), func(k string) string { return k }).Draw(pt, "rightKeys")
		}
		build := func(ks []string) (cedar.Context, cedar.EvalRecord) {
			record, want := cedar.Record{}, cedar.EvalRecord{}
			for _, k := range ks {
				value := propUtilGenScalar().Draw(pt, "value")
				record[k] = value
				want[k] = propUtilEvalOf(value)
			}
			return cedar.NewContext(record), want
		}
		left, wantLeft := build(leftKeys)
		right, wantRight := build(rightKeys)
		wantUnion := cedar.EvalRecord{}
		for _, want := range []cedar.EvalRecord{wantLeft, wantRight} {
			for k, v := range want {
				wantUnion[k] = v
			}
		}
		merged, err := left.Merge(ctx, rt, right)
		if err != nil {
			pt.Fatal(err)
		}
		values, err := merged.Values(ctx, rt)
		if err != nil || !reflect.DeepEqual(values, wantUnion) {
			pt.Fatalf("merged values: %#v want %#v %v", values, wantUnion, err)
		}
		reverse, err := right.Merge(ctx, rt, left)
		if err != nil {
			pt.Fatal(err)
		}
		reverseValues, err := reverse.Values(ctx, rt)
		if err != nil || !reflect.DeepEqual(reverseValues, values) {
			pt.Fatalf("merge order changed values: %#v vs %#v %v", reverseValues, values, err)
		}
		// Overlapping keys are rejected even when both sides carry the equal value.
		shared := rapid.SampledFrom(keys).Draw(pt, "sharedKey")
		others := slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return k == shared })
		leftExtra := rapid.SampledFrom(others).Draw(pt, "leftExtra")
		rightExtras := slices.DeleteFunc(slices.Clone(others), func(k string) bool { return k == leftExtra })
		sharedValue := propUtilGenScalar().Draw(pt, "sharedValue")
		l := cedar.Record{shared: sharedValue}
		l[leftExtra] = propUtilGenScalar().Draw(pt, "leftValue")
		r := cedar.Record{shared: sharedValue}
		rightExtra := rapid.SampledFrom(rightExtras).Draw(pt, "rightExtra")
		r[rightExtra] = propUtilGenScalar().Draw(pt, "rightValue")
		result, err := cedar.NewContext(l).Merge(ctx, rt, cedar.NewContext(r))
		var ce *cedar.Error
		if !errors.As(err, &ce) || ce.Kind != cedar.KindContext {
			pt.Fatalf("shared key %q accepted: %+v %v", shared, result, err)
		}
	})
}
