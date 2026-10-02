package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFormatEncodedLimits(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	const source = `// <>&` + "\n" + `permit(principal,action,resource);`
	in, err := json.Marshal(formatInput{Text: source, formatConfig: formatConfig{80, 2, DefaultMaxResponseBytes}})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{len(source) - 1, len(in) - 1} {
		bounded := *rt
		bounded.maxSourceBytes = limit
		out, err := bounded.FormatPolicies(ctx, source)
		var e *Error
		if out != "" || !errors.As(err, &e) || e.Kind != KindLimit {
			t.Fatalf("input limit %d: %q, %v", limit, out, err)
		}
	}
	bounded := *rt
	bounded.maxSourceBytes = len(in)
	out, err := bounded.FormatPolicies(ctx, source)
	if err != nil || out == "" {
		t.Fatalf("exact encoded input limit: %q, %v", out, err)
	}
	// Measure Rust's encoding; Go and serde_json escape HTML characters differently.
	encoded, err := rt.callOnce(ctx, "cgw_format", in)
	if err != nil {
		t.Fatal(err)
	}
	bounded.maxResponse = uint32(len(encoded) - 1)
	got, err := bounded.FormatPolicies(ctx, source)
	if got != "" || !errors.Is(err, ErrFault) {
		t.Fatalf("encoded output limit: %q, %v", got, err)
	}
	bounded.maxResponse++
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
		out, err := decodeFormatOutput([]byte(body), 1)
		if out != "" || !errors.Is(err, ErrFault) {
			t.Fatalf("%s: %q, %v", body, out, err)
		}
	}
}

func TestFormatGuestCancellationAndEnvelope(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	for _, input := range []string{
		`{}`, `{"text":"","line_width":-1,"indent_width":2,"max_output_bytes":100}`,
		`{"text":"","line_width":4294967296,"indent_width":2,"max_output_bytes":100}`,
		`{"text":"","line_width":80,"indent_width":2147483648,"max_output_bytes":100}`,
		`{"text":"","line_width":80,"indent_width":2,"max_output_bytes":0}`,
		`{"text":"","line_width":80,"indent_width":2,"max_output_bytes":16777217}`,
		`{"text":"","line_width":80,"indent_width":2,"max_output_bytes":100,"extra":true}`,
	} {
		out, err := rt.callOnce(ctx, "cgw_format", []byte(input))
		if err != nil {
			t.Fatal(err)
		}
		text, err := decodeFormatOutput(out, 100)
		var e *Error
		if text != "" || !errors.As(err, &e) || e.Kind != KindInput {
			t.Fatalf("guest envelope %s: %q, %v", input, text, err)
		}
	}
	inst, err := rt.module.Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close(ctx)
	input, err := json.Marshal(formatInput{
		Text:         strings.Repeat("permit(principal,action,resource);\n", 20000),
		formatConfig: formatConfig{80, 2, DefaultMaxResponseBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Compilation, instantiation and host encoding have finished before the timer starts.
	timed, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := inst.Call(timed, "cgw_format", input, rt.maxResponse)
	if out != nil || !errors.Is(err, context.DeadlineExceeded) || !inst.Faulted() || time.Since(start) > 2*time.Second {
		t.Fatalf("in-flight cancellation: %q, %v, faulted=%v", out, err, inst.Faulted())
	}
}
