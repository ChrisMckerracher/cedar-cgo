package cedar_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/tetratelabs/wazero"
)

// A denial under permitAll can only come from the fail-closed path.
var permitAll = cedar.PoliciesFromCedar("permit(principal, action, resource);")

func simpleRequest(ctx cedar.Context) cedar.Request {
	return cedar.Request{
		Principal: cedar.NewEntityUID("User", "alice"),
		Action:    cedar.NewEntityUID("Action", "view"),
		Resource:  cedar.NewEntityUID("Photo", "p1"),
		Context:   ctx,
	}
}

var testCache = wazero.NewCompilationCache()

func requireFaultThenRecovery(t *testing.T, a *cedar.Authorizer, resp cedar.Response, err error, wantStderr string) {
	t.Helper()
	if resp.Decision != cedar.Deny {
		t.Fatalf("faulted call returned %v, want deny", resp.Decision)
	}
	if !errors.Is(err, cedar.ErrFault) {
		t.Fatalf("got error %v, want a fault", err)
	}
	if wantStderr != "" && !strings.Contains(err.Error(), wantStderr) {
		t.Fatalf("fault %q does not mention %q", err, wantStderr)
	}
	before := a.Stats()
	if before.Discarded != 1 {
		t.Fatalf("stats after fault: %+v, want 1 discarded instance", before)
	}
	resp, err = a.Authorize(context.Background(), simpleRequest(cedar.Context{}))
	if err != nil || resp.Decision != cedar.Allow {
		t.Fatalf("call after fault: %+v, %v; want allow", resp, err)
	}
	if after := a.Stats(); after.Created != before.Created+1 {
		t.Fatalf("call after fault did not create a fresh instance: before %+v, after %+v", before, after)
	}
}

func TestFailClosedOnMemoryLimit(t *testing.T) {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx, cedar.WithMemoryLimit(16<<20), cedar.WithCompilationCache(testCache))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	a, err := rt.NewAuthorizer(ctx, cedar.Config{
		Policies: permitAll,
		Limits:   cedar.Limits{MaxInstances: 1, MaxRequestBytes: 64 << 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// The 4 MiB string fits in the input buffer, but Cedar's copies of it do
	// not fit in 16 MiB. Rust aborts on the failed allocation.
	big := cedar.NewContext(cedar.Record{"s": cedar.String(strings.Repeat("x", 4<<20))})
	resp, err := a.Authorize(ctx, simpleRequest(big))
	requireFaultThenRecovery(t, a, resp, err, "memory allocation")
}

func TestFailClosedOnTimeout(t *testing.T) {
	a, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{
		Policies: cedar.PoliciesFromCedar("permit(principal, action, resource) unless { context has a && context.a.contains(-1) };"),
		Limits:   cedar.Limits{MaxInstances: 1, MaxRequestBytes: 64 << 20, CallTimeout: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// A set of 20,000 numbers takes Cedar about 400 ms to parse here.
	var sb strings.Builder
	sb.WriteString(`{"a":[`)
	for i := range 20000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(i))
	}
	sb.WriteString(`]}`)
	start := time.Now()
	resp, err := a.Authorize(context.Background(), simpleRequest(cedar.ContextFromJSON([]byte(sb.String()))))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timed-out call took %v", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got error %v, want a deadline", err)
	}
	requireFaultThenRecovery(t, a, resp, err, "")
}

func TestFailClosedOnCallerCancel(t *testing.T) {
	a, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{
		Policies: permitAll,
		Limits:   cedar.Limits{MaxInstances: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := a.Authorize(ctx, simpleRequest(cedar.Context{}))
	if resp.Decision != cedar.Deny || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled call: %+v, %v; want deny and context.Canceled", resp, err)
	}
}

func TestFailClosedOnStackOverflow(t *testing.T) {
	rt := testRuntime(t)
	// 800 nested parentheses exhaust the guest's 8 MiB stack, exercising host survival.
	deep := "permit(principal, action, resource) when { " + strings.Repeat("(", 800) + "true" + strings.Repeat(")", 800) + " };"
	_, err := rt.NewAuthorizer(context.Background(), cedar.Config{Policies: cedar.PoliciesFromCedar(deep)})
	if !errors.Is(err, cedar.ErrFault) {
		t.Fatalf("got %v, want a fault", err)
	}
	_, err = rt.Validate(context.Background(), cedar.SchemaFromCedar(""), cedar.PoliciesFromCedar(deep))
	if !errors.Is(err, cedar.ErrFault) {
		t.Fatalf("validate: got %v, want a fault", err)
	}
	shallow := "permit(principal, action, resource) when { " + strings.Repeat("(", 400) + "true" + strings.Repeat(")", 400) + " };"
	a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Policies: cedar.PoliciesFromCedar(shallow)})
	if err != nil {
		t.Fatalf("400 nested parentheses: %v", err)
	}
	a.Close()
}

func TestRequestSizeLimit(t *testing.T) {
	a, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{
		Policies: permitAll,
		Limits:   cedar.Limits{MaxRequestBytes: 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	resp, err := a.Authorize(context.Background(), simpleRequest(cedar.NewContext(cedar.Record{"s": cedar.String(strings.Repeat("x", 2048))})))
	var cerr *cedar.Error
	if resp.Decision != cedar.Deny || !errors.As(err, &cerr) || cerr.Kind != cedar.KindLimit {
		t.Fatalf("oversized request: %+v, %v; want deny and a limit error", resp, err)
	}
}
