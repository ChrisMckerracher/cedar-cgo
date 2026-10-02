package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	"github.com/tetratelabs/wazero"
)

func templateRuntime(t *testing.T, options ...RuntimeOption) *Runtime {
	t.Helper()
	cache, err := wazero.NewCompilationCacheWithDir(filepath.Join(os.TempDir(), "cedar-go-wasm-test-cache"))
	if err != nil {
		t.Fatal(err)
	}
	options = append(options, WithCompilationCache(cache))
	rt, err := NewRuntime(context.Background(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()); _ = cache.Close(context.Background()) })
	return rt
}

func TestTemplateResourceAndLifecycle(t *testing.T) {
	ctx := context.Background()
	rt := templateRuntime(t)
	op := struct {
		Op string `json:"op"`
	}{"templates"}
	in, err := json.Marshal(templateInput{Policies: PolicySet{}.wire(), Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	rt.maxSourceBytes = len(in)
	if _, err := rt.Templates(ctx, PolicySet{}); err != nil {
		t.Fatalf("exact input boundary: %v", err)
	}
	rt.maxSourceBytes--
	if _, err := rt.Templates(ctx, PolicySet{}); !isTemplateError(err, KindLimit) {
		t.Fatalf("above boundary: %v", err)
	}
	rt.maxSourceBytes = DefaultMaxSourceBytes
	rt.maxResponse = 1
	if _, err := rt.Templates(ctx, PolicySet{}); !errors.Is(err, ErrFault) {
		t.Fatalf("response limit: %v", err)
	}
	rt.maxResponse = DefaultMaxResponseBytes
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := rt.Templates(cancelled, PolicySet{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call: %v", err)
	}
	deadline, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	defer stop()
	large := PoliciesFromCedar(strings.Repeat("permit(principal, action, resource);\n", 20000))
	if _, err := rt.Templates(deadline, large); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline call: %v", err)
	}
	if _, err := rt.AddTemplate(ctx, PolicySet{}, "fresh", TemplateFromCedar("permit(principal == ?principal, action, resource);")); err != nil {
		t.Fatalf("runtime after fault/cancellation: %v", err)
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Templates(ctx, PolicySet{}); !errors.Is(err, ErrFault) {
		t.Fatalf("closed runtime: %v", err)
	}
}

func TestTemplateMemoryLimit(t *testing.T) {
	rt := templateRuntime(t, WithMemoryLimit(16<<20))
	ctx := context.Background()
	large := TemplateFromCedar(`@large("` + strings.Repeat("x", 8<<20) + `") permit(principal == ?principal, action, resource);`)
	if _, err := rt.AddTemplate(ctx, PolicySet{}, "large", large); !errors.Is(err, ErrFault) {
		t.Fatalf("memory limit: %v", err)
	}
	if _, err := rt.Templates(ctx, PolicySet{}); err != nil {
		t.Fatalf("fresh instance after memory fault: %v", err)
	}
}

func isTemplateError(err error, kind ErrorKind) bool {
	var ce *Error
	return errors.As(err, &ce) && ce.Kind == kind
}

func TestTemplateWireRejectsMalformedEnvelope(t *testing.T) {
	rt := templateRuntime(t)
	for _, input := range []string{
		`{`, `null`, `{}`, `{"policies":{"format":"cedar","text":""},"operation":{"op":"oops"}}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"templates","extra":true}}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"links","extra":true}}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"templates"},"extra":true}`,
		`{"policies":{"format":"cedar","text":""},"operation":{"op":"link","template_id":"t","policy_id":"p","bindings":null}}`,
		`{"policies":{"format":"unknown","text":""},"operation":{"op":"templates"}}`,
	} {
		out, err := rt.callOnce(context.Background(), "cgw_templates", []byte(input))
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
