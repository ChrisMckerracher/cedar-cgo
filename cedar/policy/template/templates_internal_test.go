package template

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"

	strings "strings"
	testing "testing"
	time "time"
)

func TemplateRuntime(t *testing.T, options ...execution.Option) *Client {
	t.Helper()
	rt, err := newRuntime(context.Background(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.runtime.Close(context.Background()) })
	return rt
}

func TestTemplateResourceAndLifecycle(t *testing.T) {
	ctx := context.Background()
	rt := TemplateRuntime(t)
	op := struct {
		Op string `json:"op"`
	}{"templates"}
	in, err := json.Marshal(TemplateInput{Policies: cedarpolicy.PolicySet{}.Wire(), Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	rt.runtime.MaxSourceBytes = len(in)
	if _, err := rt.Templates(ctx, cedarpolicy.PolicySet{}); err != nil {
		t.Fatalf("exact input boundary: %v", err)
	}
	rt.runtime.MaxSourceBytes--
	if _, err := rt.Templates(ctx, cedarpolicy.PolicySet{}); !IsTemplateError(err, diagnostic.KindLimit) {
		t.Fatalf("above boundary: %v", err)
	}
	rt.runtime.MaxSourceBytes = execution.DefaultMaxSourceBytes
	rt.runtime.MaxResponse = 1
	if _, err := rt.Templates(ctx, cedarpolicy.PolicySet{}); !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("response limit: %v", err)
	}
	rt.runtime.MaxResponse = execution.DefaultMaxResponseBytes
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := rt.Templates(cancelled, cedarpolicy.PolicySet{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call: %v", err)
	}
	deadline, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	defer stop()
	large := cedarpolicy.PoliciesFromCedar(strings.Repeat("permit(principal, action, resource);\n", 20000))
	if _, err := rt.Templates(deadline, large); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline call: %v", err)
	}
	if _, err := rt.AddTemplate(ctx, cedarpolicy.PolicySet{}, "fresh", TemplateFromCedar("permit(principal == ?principal, action, resource);")); err != nil {
		t.Fatalf("runtime after fault/cancellation: %v", err)
	}
	if err := rt.runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Templates(ctx, cedarpolicy.PolicySet{}); !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("closed runtime: %v", err)
	}
}

func TestTemplateMemoryLimit(t *testing.T) {
	if rt, err := newRuntime(context.Background(), execution.WithMemoryLimit(16<<20)); err == nil {
		rt.runtime.Close(context.Background())
		t.Fatal("native memory option accepted")
	}
	rt := TemplateRuntime(t, execution.WithMaxSourceBytes(1024))
	ctx := context.Background()
	large := TemplateFromCedar(`@large("` + strings.Repeat("x", 8<<20) + `") permit(principal == ?principal, action, resource);`)
	if _, err := rt.AddTemplate(ctx, cedarpolicy.PolicySet{}, "large", large); !IsTemplateError(err, diagnostic.KindLimit) {
		t.Fatalf("source limit: %v", err)
	}
	if _, err := rt.Templates(ctx, cedarpolicy.PolicySet{}); err != nil {
		t.Fatal(err)
	}
}

func IsTemplateError(err error, kind diagnostic.ErrorKind) bool {
	var ce *diagnostic.Error
	return errors.As(err, &ce) && ce.Kind == kind
}

func TestTemplateWireRejectsMalformedEnvelope(t *testing.T) {
	rt := TemplateRuntime(t)
	for _, input := range []string{
		`{`, `null`, `{}`, `{"policies":{"format":"cedar","text":""},"operation":{"op":"oops"}}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"templates","extra":true}}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"links","extra":true}}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"templates"},"extra":true}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"link","template_id":"t","policy_id":"p","bindings":null}}`,
		`{"policies":{"format":"unknown","text":""},"operation":{"op":"templates"}}`,
	} {
		out, err := rt.runtime.CallOnce(context.Background(), "cgw_templates", []byte(input))
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Error *wire.Error `json:"error"`
		}
		if err := json.Unmarshal(out, &response); err != nil {
			t.Fatal(err)
		}
		if response.Error == nil || response.Error.Kind != "input" {
			t.Fatalf("input %s: %s", input, out)
		}
	}
}
