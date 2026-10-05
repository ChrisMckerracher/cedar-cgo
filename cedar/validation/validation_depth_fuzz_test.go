package validation_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzValidationDepth(f *testing.F) {
	d := testsupport.LoadJoy(f)
	rt := testsupport.TestRuntime(f)
	f.Add(`permit(principal, action, resource) when { principal.photo.owner.admin };`, uint8(3))
	f.Add(`permit(principal, action, resource);`, uint8(0))
	f.Add("", uint8(2))
	f.Add("\xff", uint8(1))
	f.Add(`permit(principal, action, resource) when { context.deviceLevel == true };`, uint8(4))
	f.Fuzz(func(t *testing.T, TextValue string, level uint8) {
		if testsupport.Nesting(TextValue) > testsupport.MaxFuzzNesting {
			t.Skip()
		}
		policies := cedarpolicy.PoliciesFromCedar(TextValue)
		ctx := context.Background()
		if !utf8.ValidString(TextValue) {
			_, err := rt.Validation().ValidateWithLevel(ctx, d.Schema, policies, uint32(level))
			testsupport.RequireUTF8InputError(t, err)
			return
		}
		first, err := rt.Validation().ValidateWithLevel(ctx, d.Schema, policies, uint32(level))
		testsupport.CheckNoFault(t, err)
		second, errAgain := rt.Validation().ValidateWithLevel(ctx, d.Schema, policies, uint32(level))
		testsupport.CheckNoFault(t, errAgain)
		if !reflect.DeepEqual(generator.PropStableValidation(first), generator.PropStableValidation(second)) || !reflect.DeepEqual(err, errAgain) {
			t.Fatalf("level %d validation is not deterministic: (%v, %v) vs (%v, %v)",
				level, first, err, second, errAgain)
		}
		// Parse and schema rejections are outside the depth claim; skip them.
		if err != nil {
			return
		}
		higher, err := rt.Validation().ValidateWithLevel(ctx, d.Schema, policies, uint32(level)+1)
		testsupport.CheckNoFault(t, err)
		if err != nil {
			return
		}
		if first.Passed && !higher.Passed {
			t.Fatalf("passes at level %d but fails at %d\n%s", level, level+1, TextValue)
		}
	})
}
