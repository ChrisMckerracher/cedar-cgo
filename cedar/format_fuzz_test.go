package cedar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzFormatPolicies(f *testing.F) {
	rt := testRuntime(f)
	f.Add(`permit(principal,action,resource);`, uint8(80), int8(2))
	f.Add("// comment\n@id(\"é\") permit(principal==?principal,action,resource);", uint8(20), int8(0))
	f.Add(`permit(principal,action,resource)when{context.x like "*"};`, uint8(0), int8(-2))
	f.Add("\xff\x00", uint8(255), int8(127))
	f.Fuzz(func(t *testing.T, text string, width uint8, indent int8) {
		if len(text) > 4096 || nesting(text) > 40 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		opts := []cedar.FormatOption{
			cedar.WithFormatLineWidth(uint32(width)), cedar.WithFormatIndentWidth(int32(indent)),
			cedar.WithFormatMaxOutputBytes(1 << 20),
		}
		out, err := rt.FormatPolicies(ctx, text, opts...)
		if err != nil {
			if out != "" || errors.Is(err, cedar.ErrFault) {
				t.Fatalf("bounded format failed: %q, %v", out, err)
			}
			return
		}
		again, err := rt.FormatPolicies(ctx, out, opts...)
		if err != nil || again != out {
			t.Fatalf("not idempotent: first %q, second %q, %v", out, again, err)
		}
	})
}
