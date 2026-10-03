package cedar_test

import (
	"context"
	"reflect"
	"testing"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzValidationDepth(f *testing.F) {
	d := loadJoy(f)
	rt := testRuntime(f)
	f.Add(`permit(principal, action, resource) when { principal.photo.owner.admin };`, uint8(3))
	f.Add(`permit(principal, action, resource);`, uint8(0))
	f.Add("", uint8(2))
	f.Add("\xff", uint8(1))
	f.Add(`permit(principal, action, resource) when { context.deviceLevel == true };`, uint8(4))
	f.Fuzz(func(t *testing.T, text string, level uint8) {
		if nesting(text) > maxFuzzNesting {
			t.Skip()
		}
		policies := cedar.PoliciesFromCedar(text)
		ctx := context.Background()
		if !utf8.ValidString(text) {
			_, err := rt.ValidateWithLevel(ctx, d.schema, policies, uint32(level))
			requireUTF8InputError(t, err)
			return
		}
		first, err := rt.ValidateWithLevel(ctx, d.schema, policies, uint32(level))
		checkNoFault(t, err)
		second, errAgain := rt.ValidateWithLevel(ctx, d.schema, policies, uint32(level))
		checkNoFault(t, errAgain)
		if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(err, errAgain) {
			t.Fatalf("level %d validation is not deterministic: (%v, %v) vs (%v, %v)",
				level, first, err, second, errAgain)
		}
		// Parse and schema rejections are outside the depth claim; skip them.
		if err != nil {
			return
		}
		higher, err := rt.ValidateWithLevel(ctx, d.schema, policies, uint32(level)+1)
		checkNoFault(t, err)
		if err != nil {
			return
		}
		if first.Passed && !higher.Passed {
			t.Fatalf("passes at level %d but fails at %d\n%s", level, level+1, text)
		}
	})
}
