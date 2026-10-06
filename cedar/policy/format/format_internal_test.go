package format

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"
	strings "strings"
	testing "testing"
	time "time"
)

func TestFormatEncodedLimits(t *testing.T) {
	ctx := context.Background()
	rt, err := newRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(ctx)
	const source = `// <>&` + "\n" + `permit(principal,action,resource);`
	in, err := json.Marshal(FormatInput{Text: source, FormatConfig: FormatConfig{80, 2, execution.DefaultMaxResponseBytes}})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{len(source) - 1, len(in) - 1} {
		bounded := *rt
		config := *rt.runtime
		bounded.runtime = &config
		bounded.runtime.MaxSourceBytes = limit
		out, err := bounded.FormatPolicies(ctx, source)
		var e *diagnostic.Error
		if out != "" || !errors.As(err, &e) || e.Kind != diagnostic.KindLimit {
			t.Fatalf("input limit %d: %q, %v", limit, out, err)
		}
	}
	bounded := *rt
	config := *rt.runtime
	bounded.runtime = &config
	bounded.runtime.MaxSourceBytes = len(in)
	out, err := bounded.FormatPolicies(ctx, source)
	if err != nil || out == "" {
		t.Fatalf("exact encoded input limit: %q, %v", out, err)
	}
	// Measure Rust's encoding; Go and serde_json escape HTML characters differently.
	encoded, err := rt.runtime.CallOnce(ctx, "cgw_format", in)
	if err != nil {
		t.Fatal(err)
	}
	bounded.runtime.MaxResponse = uint32(len(encoded) - 1)
	got, err := bounded.FormatPolicies(ctx, source)
	if got != "" || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("encoded output limit: %q, %v", got, err)
	}
	bounded.runtime.MaxResponse++
	got, err = bounded.FormatPolicies(ctx, source)
	if err != nil || got != out {
		t.Fatalf("exact encoded output limit: %q, %v", got, err)
	}
}

func TestFormatRejectsBrokenResponses(t *testing.T) {
	for _, body := range []string{
		`{`, `null`, `{}`, `{"formatted":null}`, `{"formatted":42}`,
		`{"formatted":"x","error":{"kind":"policies","message":"bad"}}`,
		`{"error":{"kind":"mystery","message":"bad"}}`, `{"formatted":"too long"}`,
	} {
		out, err := DecodeFormatOutput([]byte(body), 1)
		if out != "" || !errors.Is(err, diagnostic.ErrFault) {
			t.Fatalf("%s: %q, %v", body, out, err)
		}
	}
}

func TestFormatGuestCancellationAndEnvelope(t *testing.T) {
	ctx := context.Background()
	rt, err := newRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(ctx)
	for _, input := range []string{
		`{}`, `{"text":"","line_width":-1,"indent_width":2,"max_output_bytes":100}`,
		`{"text":"","line_width":4294967296,"indent_width":2,"max_output_bytes":100}`,
		`{"text":"","line_width":80,"indent_width":2147483648,"max_output_bytes":100}`,
		`{"text":"","line_width":80,"indent_width":2,"max_output_bytes":0}`,
		`{"text":"","line_width":80,"indent_width":2,"max_output_bytes":16777217}`,
		`{"text":"","line_width":80,"indent_width":2,"max_output_bytes":100,"extra":true}`,
	} {
		out, err := rt.runtime.CallOnce(ctx, "cgw_format", []byte(input))
		if err != nil {
			t.Fatal(err)
		}
		TextValue, err := DecodeFormatOutput(out, 100)
		var e *diagnostic.Error
		if TextValue != "" || !errors.As(err, &e) || e.Kind != diagnostic.KindInput {
			t.Fatalf("native envelope %s: %q, %v", input, TextValue, err)
		}
	}
	inst, err := rt.runtime.Module.Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close(ctx)
	input, err := json.Marshal(FormatInput{
		Text:         strings.Repeat("permit(principal,action,resource);\n", 20000),
		FormatConfig: FormatConfig{80, 2, execution.DefaultMaxResponseBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Compilation, instantiation and host encoding have finished before the timer starts.
	timed, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	out, err := inst.Call(timed, "cgw_format", input, rt.runtime.MaxResponse)
	if out != nil || !errors.Is(err, context.DeadlineExceeded) || !inst.Faulted() {
		t.Fatalf("in-flight cancellation: %q, %v, faulted=%v", out, err, inst.Faulted())
	}
}
