package integration_test

import (
	context "context"
	errors "errors"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	strconv "strconv"
	strings "strings"
	testing "testing"
	"testing/synctest"
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
	synctest.Test(t, func(t *testing.T) {
		rt, err := cedar.NewRuntime(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close(context.Background())
		schema := cedarschema.SchemaFromCedar(`entity User { active: Bool }; entity Photo; action "view" appliesTo { principal: User, resource: Photo, context: { a?: Set<Long> } };`)
		a, err := rt.NewAuthorizer(context.Background(), authorization.Config{
			Schema:   &schema,
			Policies: cedarpolicy.PoliciesFromCedar("permit(principal, action, resource) when { !(context has a) || principal.active } unless { context has a && context.a.contains(-1) };"),
			Limits:   authorization.Limits{MaxInstances: 1, MaxRequestBytes: 64 << 20, CallTimeout: time.Second},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		// Fake time stops during parsing and expires only after the loader blocks.
		var sb strings.Builder
		sb.WriteString(`{"a":[`)
		for i := range 100000 {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(strconv.Itoa(i))
		}
		sb.WriteString(`]}`)
		entered := false
		start := time.Now()
		decision, err := a.Batched().AuthorizeBatched(context.Background(), testsupport.SimpleRequest(request.ContextFromJSON([]byte(sb.String()))), batched.EntityLoaderFunc(func(ctx context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			entered = true
			<-ctx.Done()
			return batched.EntityLoadResult{Missing: uids}, nil
		}), batched.BatchedOptions{MaxIterations: 2})
		if !entered {
			t.Fatal("deadline expired before the native loader callback")
		}
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Fatalf("call elapsed %v, want the one-second deadline", elapsed)
		}
		resp := request.Response{Decision: decision}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got error %v, want a deadline", err)
		}
		testsupport.RequireFaultThenRecovery(t, a, resp, err, "")
	})
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
