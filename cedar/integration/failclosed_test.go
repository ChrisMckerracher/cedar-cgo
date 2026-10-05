package integration_test

import (
	context "context"
	errors "errors"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	strconv "strconv"
	strings "strings"
	testing "testing"
	time "time"
)

func TestFailClosedOnMemoryLimit(t *testing.T) {
	for name, option := range map[string]cedar.RuntimeOption{
		"WithMemoryLimit":      cedar.WithMemoryLimit(16 << 20),
		"WithCompilationCache": cedar.WithCompilationCache(struct{}{}),
	} {
		t.Run(name, func(t *testing.T) {
			rt, err := cedar.NewRuntime(context.Background(), option)
			if rt != nil || err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("native runtime accepted %s: %v", name, err)
			}
		})
	}
	authorizer, err := testsupport.TestRuntime(t).NewAuthorizer(context.Background(), authorization.Config{
		Policies: testsupport.PermitAll,
		Limits:   authorization.Limits{RecycleMemoryBytes: 1},
	})
	if authorizer != nil || err == nil || !strings.Contains(err.Error(), "RecycleMemoryBytes") {
		t.Fatalf("native runtime accepted memory recycling: %v", err)
	}
}

func TestFailClosedOnTimeout(t *testing.T) {
	a, err := testsupport.TestRuntime(t).NewAuthorizer(context.Background(), authorization.Config{
		Policies: cedarpolicy.PoliciesFromCedar("permit(principal, action, resource) unless { context has a && context.a.contains(-1) };"),
		Limits:   authorization.Limits{MaxInstances: 1, MaxRequestBytes: 64 << 20, CallTimeout: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// Native CPU work must return before the canceled result can be rejected.
	var sb strings.Builder
	sb.WriteString(`{"a":[`)
	for i := range 100000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(i))
	}
	sb.WriteString(`]}`)
	resp, err := a.Authorize(context.Background(), testsupport.SimpleRequest(request.ContextFromJSON([]byte(sb.String()))))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got error %v, want a deadline", err)
	}
	testsupport.RequireFaultThenRecovery(t, a, resp, err, "")
}

func TestFailClosedOnCallerCancel(t *testing.T) {
	a, err := testsupport.TestRuntime(t).NewAuthorizer(context.Background(), authorization.Config{
		Policies: testsupport.PermitAll,
		Limits:   authorization.Limits{MaxInstances: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := a.Authorize(ctx, testsupport.SimpleRequest(request.Context{}))
	if resp.Decision != request.Deny || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled call: %+v, %v; want deny and context.Canceled", resp, err)
	}
}

func TestRequestSizeLimit(t *testing.T) {
	a, err := testsupport.TestRuntime(t).NewAuthorizer(context.Background(), authorization.Config{
		Policies: testsupport.PermitAll,
		Limits:   authorization.Limits{MaxRequestBytes: 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	resp, err := a.Authorize(context.Background(), testsupport.SimpleRequest(request.NewContext(cedarvalue.Record{"s": cedarvalue.String(strings.Repeat("x", 2048))})))
	var cerr *diagnostic.Error
	if resp.Decision != request.Deny || !errors.As(err, &cerr) || cerr.Kind != diagnostic.KindLimit {
		t.Fatalf("oversized request: %+v, %v; want deny and a limit error", resp, err)
	}
}
