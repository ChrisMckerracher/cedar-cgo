package policy

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	strings "strings"
	testing "testing"
	time "time"
)

func TestPolicyOperationLimits(t *testing.T) {
	ctx := context.Background()
	rt, err := newRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(ctx)
	input := map[string]any{"op": "parse", "id": "boundary", "source": wire.Source{Format: "cedar", Text: "permit(principal,action,resource);"}}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	rt.runtime.MaxSourceBytes = len(encoded)
	if _, err := rt.ParsePolicy(ctx, "boundary", "permit(principal,action,resource);"); err != nil {
		t.Fatal("exact limit rejected:", err)
	}
	rt.runtime.MaxSourceBytes--
	if _, err := rt.ParsePolicy(ctx, "boundary", "permit(principal,action,resource);"); err == nil {
		t.Fatal("oversized envelope accepted")
	} else {
		var e *diagnostic.Error
		if !errors.As(err, &e) || e.Kind != diagnostic.KindLimit {
			t.Fatal(err)
		}
	}
	rt.runtime.MaxSourceBytes = execution.DefaultMaxSourceBytes
	rt.runtime.MaxResponse = 16
	if _, err := rt.ParsePolicy(ctx, "response", "permit(principal,action,resource);"); !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("response limit: %v", err)
	}
	rt.runtime.MaxResponse = execution.DefaultMaxResponseBytes
	if _, err := rt.ParsePolicy(ctx, "fresh", "permit(principal,action,resource);"); err != nil {
		t.Fatal(err)
	}
	// The source is valid but cannot finish within this deadline, exercising native result rejection.
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
	rt, err := newRuntime(context.Background(), execution.WithMaxSourceBytes(1024))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(context.Background())
	_, err = rt.ParsePolicySet(context.Background(), PoliciesFromCedar(strings.Repeat("permit(principal,action,resource);", 20000)))
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit {
		t.Fatalf("source bound: %v", err)
	}
	if _, err := rt.ParsePolicySet(context.Background(), PoliciesFromCedar("")); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyProtocolRejectsUnknownFields(t *testing.T) {
	ctx := context.Background()
	rt, err := newRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(ctx)
	for _, input := range []string{`{"op":"inspect","set":{"format":"cedar","text":""},"extra":true}`, `{"op":"missing"}`, `{`, `{"op":"parse","id":"p","source":{"format":"cedar","text":"permit(principal,action,resource);"},"id2":"p"}`} {
		out, err := rt.runtime.CallOnce(ctx, "cgw_policies", []byte(input))
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
