package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func TestPolicyOperationLimits(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	input := map[string]any{"op": "parse", "id": "boundary", "source": wire.Source{Format: "cedar", Text: "permit(principal,action,resource);"}}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	rt.maxSourceBytes = len(encoded)
	if _, err := rt.ParsePolicy(ctx, "boundary", "permit(principal,action,resource);"); err != nil {
		t.Fatal("exact limit rejected:", err)
	}
	rt.maxSourceBytes--
	if _, err := rt.ParsePolicy(ctx, "boundary", "permit(principal,action,resource);"); err == nil {
		t.Fatal("oversized envelope accepted")
	} else {
		var e *Error
		if !errors.As(err, &e) || e.Kind != KindLimit {
			t.Fatal(err)
		}
	}
	rt.maxSourceBytes = DefaultMaxSourceBytes
	rt.maxResponse = 16
	if _, err := rt.ParsePolicy(ctx, "response", "permit(principal,action,resource);"); !errors.Is(err, ErrFault) {
		t.Fatalf("response limit: %v", err)
	}
	rt.maxResponse = DefaultMaxResponseBytes
	if _, err := rt.ParsePolicy(ctx, "fresh", "permit(principal,action,resource);"); err != nil {
		t.Fatal(err)
	}
	// The source is valid but cannot finish within this deadline, exercising guest interruption.
	deadline, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	_, err = rt.ParsePolicySet(deadline, PoliciesFromCedar(strings.Repeat("permit(principal,action,resource);", 20000)))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("active deadline: %v", err)
	}
	if _, err := rt.ParsePolicySet(ctx, PoliciesFromCedar("")); err != nil {
		t.Fatal("runtime failed after interruption:", err)
	}
}

func TestPolicyOperationMemoryLimit(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, WithMemoryLimit(16<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	_, err = rt.ParsePolicySet(ctx, PoliciesFromCedar(strings.Repeat("permit(principal,action,resource);", 20000)))
	if !errors.Is(err, ErrFault) {
		t.Fatalf("memory exhaustion must fault: %v", err)
	}
}

func TestPolicyProtocolRejectsUnknownFields(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	for _, input := range []string{`{"op":"inspect","set":{"format":"cedar","text":""},"extra":true}`, `{"op":"missing"}`, `{`, `{"op":"parse","id":"p","source":{"format":"cedar","text":"permit(principal,action,resource);"},"id2":"p"}`} {
		out, err := rt.callOnce(ctx, "cgw_policies", []byte(input))
		if err != nil {
			t.Fatal(err)
		}
		var envelope policyOutput
		if err := json.Unmarshal(out, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Error == nil || envelope.Error.Kind != "input" {
			t.Fatalf("unexpected response: %s", out)
		}
	}
}
