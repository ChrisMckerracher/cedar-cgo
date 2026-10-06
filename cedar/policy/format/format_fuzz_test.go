package format_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	policyformat "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/format"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"
	joy "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
	time "time"
	utf8 "unicode/utf8"
)

func FuzzFormatPolicies(f *testing.F) {
	rt := testruntime.New(f)
	d := joy.LoadJoy(f)
	f.Add(`permit(principal,action,resource);`, uint8(80), int8(2))
	f.Add("// comment\n@id(\"é\") permit(principal==?principal,action,resource);", uint8(20), int8(0))
	f.Add(`permit(principal,action,resource)when{context.x like "*"};`, uint8(0), int8(-2))
	f.Add("\xff\x00", uint8(255), int8(127))
	f.Fuzz(func(t *testing.T, TextValue string, width uint8, indent int8) {
		if len(TextValue) > 4096 || fuzz.Nesting(TextValue) > 40 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		opts := []policyformat.FormatOption{
			policyformat.WithFormatLineWidth(uint32(width)), policyformat.WithFormatIndentWidth(int32(indent)),
			policyformat.WithFormatMaxOutputBytes(1 << 20),
		}
		out, err := rt.Formatter().FormatPolicies(ctx, TextValue, opts...)
		if err != nil {
			if out != "" || errors.Is(err, diagnostic.ErrFault) {
				t.Fatalf("bounded format failed: %q, %v", out, err)
			}
			if !utf8.ValidString(TextValue) {
				fault.RequireUTF8InputError(t, err)
			}
			return
		}
		// Re-formatting proves the output re-parses and is a fixed point.
		again, err := rt.Formatter().FormatPolicies(ctx, out, opts...)
		if err != nil || again != out {
			t.Fatalf("not idempotent: first %q, second %q, %v", out, again, err)
		}
		// Formatting is semantics-preserving: the fixed request must decide
		// identically against the original and the formatted source.
		authorize := func(source string) (cedarrequest.Response, error) {
			a, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: cedarpolicy.PoliciesFromCedar(source), Entities: d.Entities, Limits: fuzz.FuzzLimits})
			if err != nil {
				fault.CheckNoFault(t, err)
				return cedarrequest.Response{Decision: cedarrequest.Deny}, err
			}
			resp, err := a.Authorize(ctx, joy.JoyRequest())
			a.Close()
			fault.CheckNoFault(t, err)
			if err != nil && resp.Decision != cedarrequest.Deny {
				t.Fatalf("error %v came with %v", err, resp.Decision)
			}
			return resp, err
		}
		before, beforeErr := authorize(TextValue)
		after, afterErr := authorize(out)
		if (beforeErr == nil) != (afterErr == nil) || before.Decision != after.Decision {
			t.Fatalf("formatting changed authorization: %v/%v became %v/%v",
				before.Decision, beforeErr, after.Decision, afterErr)
		}
	})
}
