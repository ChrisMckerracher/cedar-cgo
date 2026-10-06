package utility_test

import (
	generator "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/generator"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	context "context"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"

	rapid "pgregory.net/rapid"
	reflect "reflect"
	slices "slices"
	testing "testing"
)

func TestPropertyContextMergeDisjointKeys(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	keys := []string{"a", "b", "c", "d"}
	rapid.Check(t, func(pt *rapid.T) {
		leftKeys := rapid.SliceOfNDistinct(rapid.SampledFrom(keys), 0, 4, func(k string) string { return k }).Draw(pt, "leftKeys")
		rest := slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return slices.Contains(leftKeys, k) })
		var rightKeys []string
		if len(rest) > 0 {
			rightKeys = rapid.SliceOfNDistinct(rapid.SampledFrom(rest), 0, len(rest), func(k string) string { return k }).Draw(pt, "rightKeys")
		}
		build := func(ks []string) (cedarrequest.Context, cedarvalue.EvalRecord) {
			record, want := cedarvalue.Record{}, cedarvalue.EvalRecord{}
			for _, k := range ks {
				value := generator.PropUtilGenScalar().Draw(pt, "value")
				record[k] = value
				want[k] = generator.PropUtilEvalOf(value)
			}
			return cedarrequest.NewContext(record), want
		}
		left, wantLeft := build(leftKeys)
		right, wantRight := build(rightKeys)
		wantUnion := cedarvalue.EvalRecord{}
		for _, want := range []cedarvalue.EvalRecord{wantLeft, wantRight} {
			for k, v := range want {
				wantUnion[k] = v
			}
		}
		merged, err := left.Merge(ctx, rt.Utilities(), right)
		if err != nil {
			pt.Fatal(err)
		}
		values, err := merged.Values(ctx, rt.Utilities())
		if err != nil || !reflect.DeepEqual(values, wantUnion) {
			pt.Fatalf("merged values: %#v want %#v %v", values, wantUnion, err)
		}
		reverse, err := right.Merge(ctx, rt.Utilities(), left)
		if err != nil {
			pt.Fatal(err)
		}
		reverseValues, err := reverse.Values(ctx, rt.Utilities())
		if err != nil || !reflect.DeepEqual(reverseValues, values) {
			pt.Fatalf("merge order changed values: %#v vs %#v %v", reverseValues, values, err)
		}
		// Overlapping keys are rejected even when both sides carry the equal value.
		shared := rapid.SampledFrom(keys).Draw(pt, "sharedKey")
		others := slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return k == shared })
		leftExtra := rapid.SampledFrom(others).Draw(pt, "leftExtra")
		rightExtras := slices.DeleteFunc(slices.Clone(others), func(k string) bool { return k == leftExtra })
		sharedValue := generator.PropUtilGenScalar().Draw(pt, "sharedValue")
		l := cedarvalue.Record{shared: sharedValue}
		l[leftExtra] = generator.PropUtilGenScalar().Draw(pt, "leftValue")
		r := cedarvalue.Record{shared: sharedValue}
		rightExtra := rapid.SampledFrom(rightExtras).Draw(pt, "rightExtra")
		r[rightExtra] = generator.PropUtilGenScalar().Draw(pt, "rightValue")
		result, err := cedarrequest.NewContext(l).Merge(ctx, rt.Utilities(), cedarrequest.NewContext(r))
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != diagnostic.KindContext {
			pt.Fatalf("shared key %q accepted: %+v %v", shared, result, err)
		}
	})
}
