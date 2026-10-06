package utility_test

import (
	bytes "bytes"
	context "context"
	json "encoding/json"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	rapid "pgregory.net/rapid"
	reflect "reflect"
	testing "testing"
)

func TestNativeUIDRoundTripProperty(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		id := rapid.StringN(0, 40, 160).Draw(pt, "id")
		typ := rapid.SampledFrom([]string{"User", "NS::User", "A::B::Photo"}).Draw(pt, "type")
		uid := entityuid.NewEntityUID(typ, id)
		TextValue, err := uid.CedarText(ctx, rt.Utilities())
		if err != nil {
			pt.Fatal(err)
		}
		parsed, err := rt.Utilities().ParseEntityUID(ctx, TextValue)
		if err != nil || parsed != uid {
			pt.Fatalf("round trip %q: %+v %v", TextValue, parsed, err)
		}
		again, err := parsed.CedarText(ctx, rt.Utilities())
		if err != nil || again != TextValue {
			pt.Fatalf("unstable text %q -> %q: %v", TextValue, again, err)
		}
	})
}

func TestContextMergeContract(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	left := cedarrequest.NewContext(cedarvalue.Record{"left": cedarvalue.Record{"a": cedarvalue.Long(1)}})
	right := cedarrequest.NewContext(cedarvalue.Record{"right": cedarvalue.Set{cedarvalue.Bool(true), cedarvalue.Bool(false)}, "decimal": cedarvalue.Decimal("1.25")})
	before, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := left.Merge(ctx, rt.Utilities(), right)
	if err != nil {
		t.Fatal(err)
	}
	values, err := merged.Values(ctx, rt.Utilities())
	if err != nil || len(values) != 3 || values["decimal"] != cedarvalue.ExtensionValue(`decimal("1.25")`) {
		t.Fatalf("merge values: %#v %v", values, err)
	}
	if !reflect.DeepEqual(values["left"], cedarvalue.EvalRecord{"a": cedarvalue.Long(1)}) {
		t.Fatalf("nested value changed: %#v", values["left"])
	}
	after, err := json.Marshal(left)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("merge changed its input")
	}
	for _, other := range []cedarrequest.Context{left, cedarrequest.NewContext(cedarvalue.Record{"left": cedarvalue.Record{"b": cedarvalue.Long(2)}})} {
		result, err := left.Merge(ctx, rt.Utilities(), other)
		var ce *diagnostic.Error
		if !errors.As(err, &ce) || ce.Kind != diagnostic.KindContext {
			t.Fatalf("duplicate key accepted: %+v %v", result, err)
		}
	}
	identity, err := left.Merge(ctx, rt.Utilities(), cedarrequest.Context{})
	if err != nil {
		t.Fatal(err)
	}
	identityValues, err := identity.Values(ctx, rt.Utilities())
	leftValues, leftErr := left.Values(ctx, rt.Utilities())
	if err != nil || leftErr != nil || !reflect.DeepEqual(identityValues, leftValues) {
		t.Fatalf("empty merge changed values: %#v %#v %v %v", identityValues, leftValues, err, leftErr)
	}
}

func TestContextMergeDisjointProperty(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		a := rapid.Int64().Draw(pt, "left")
		b := rapid.StringN(0, 16, 64).Draw(pt, "right")
		left := cedarrequest.NewContext(cedarvalue.Record{"left": cedarvalue.Long(a)})
		right := cedarrequest.NewContext(cedarvalue.Record{"right": cedarvalue.String(b)})
		merged, err := left.Merge(ctx, rt.Utilities(), right)
		if err != nil {
			pt.Fatal(err)
		}
		values, err := merged.Values(ctx, rt.Utilities())
		if err != nil || !reflect.DeepEqual(values, cedarvalue.EvalRecord{"left": cedarvalue.Long(a), "right": cedarvalue.String(b)}) {
			pt.Fatalf("lost merged values: %#v %v", values, err)
		}
	})
}
