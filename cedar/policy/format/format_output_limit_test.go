package format_test

import (
	context "context"
	errors "errors"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	policyformat "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/format"
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	log "log"
	math "math"
	strings "strings"
	sync "sync"
	testing "testing"
	time "time"
)

func TestFormatOutputLimit(t *testing.T) {
	rt := testruntime.New(t)
	const input = `// café` + "\n" + `permit(principal,action,resource);`
	want, err := rt.Formatter().FormatPolicies(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := rt.Formatter().FormatPolicies(context.Background(), input, policyformat.WithFormatMaxOutputBytes(len(want)-1))
	RequireFormatError(t, out, err, diagnostic.KindLimit)
	out, err = rt.Formatter().FormatPolicies(context.Background(), input, policyformat.WithFormatMaxOutputBytes(len(want)))
	if err != nil || out != want {
		t.Fatalf("exact byte limit: %q, %v", out, err)
	}
}

func TestFormatCancellationAndIsolation(t *testing.T) {
	rt := testruntime.New(t)
	a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Policies: fault.PermitAll, Limits: authorization.Limits{MaxInstances: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := rt.Formatter().FormatPolicies(ctx, fault.PermitAll.Text())
	if out != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled format: %q, %v", out, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err = rt.Formatter().FormatPolicies(ctx, strings.Repeat(fault.PermitAll.Text()+"\n", 20000))
	if out != "" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline format: %q, %v, elapsed %v", out, err, time.Since(start))
	}
	out, err = rt.Formatter().FormatPolicies(context.Background(), fault.PermitAll.Text())
	if err != nil || out != "permit (principal, action, resource);\n" {
		t.Fatalf("format after cancellation: %q, %v", out, err)
	}
	resp, err := a.Authorize(context.Background(), fault.SimpleRequest(cedarrequest.Context{}))
	if err != nil || resp.Decision != cedarrequest.Allow || a.Stats().Created != 1 {
		t.Fatalf("format disturbed authorizer: %+v, %v, %+v", resp, err, a.Stats())
	}
}

func TestFormatMemoryAndStackLimits(t *testing.T) {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx, cedar.WithMaxSourceBytes(1024))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	out, err := rt.Formatter().FormatPolicies(ctx, "//"+strings.Repeat("x", 4<<20))
	RequireFormatError(t, out, err, diagnostic.KindLimit)
	timed, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	out, err = rt.Formatter().FormatPolicies(timed, `permit(principal,action,resource)when{true};`,
		policyformat.WithFormatLineWidth(1), policyformat.WithFormatIndentWidth(math.MaxInt32))
	RequireFormatError(t, out, err, diagnostic.KindLimit)
	out, err = rt.Formatter().FormatPolicies(ctx, fault.PermitAll.Text())
	if err != nil || out == "" {
		t.Fatalf("format after memory fault: %q, %v", out, err)
	}
	deep := "permit(principal,action,resource)when{" + strings.Repeat("(", 800) + "true" + strings.Repeat(")", 800) + "};"
	out, err = testruntime.New(t).Formatter().FormatPolicies(ctx, deep)
	RequireFormatError(t, out, err, diagnostic.KindLimit)
	out, err = testruntime.New(t).Formatter().FormatPolicies(ctx, fault.PermitAll.Text())
	if err != nil || out == "" {
		t.Fatalf("format after stack fault: %q, %v", out, err)
	}
}

func TestFormatConcurrent(t *testing.T) {
	rt := testruntime.New(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			out, err := rt.Formatter().FormatPolicies(context.Background(), fault.PermitAll.Text(), policyformat.WithFormatLineWidth(math.MaxUint32))
			if err != nil || out != "permit (principal, action, resource);\n" {
				t.Errorf("concurrent format: %q, %v", out, err)
			}
		})
	}
	wg.Wait()
}

func Example_formatPolicies() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	TextValue, err := rt.Formatter().FormatPolicies(ctx, `permit(principal,action,resource)when{context.mfa};`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(TextValue)
	// Output:
	// permit (principal, action, resource)
	// when { context.mfa };
}
