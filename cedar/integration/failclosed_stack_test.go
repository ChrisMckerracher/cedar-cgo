package integration_test

import (
	"context"
	"errors"
	"fmt"
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func nestedPolicy(depth int) policy.PolicySet {
	return policy.PoliciesFromCedar("permit(principal, action, resource) when { " + strings.Repeat("(", depth) + "true" + strings.Repeat(")", depth) + " };")
}

// Native stack overflow can abort the process; each deep-input operation owns a child.
func TestFailClosedOnStackOverflow(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"load", "validate"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeStackOverflowHelper$")
			command.Env = append(os.Environ(), "CGW_NATIVE_STACK_CHILD="+operation)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("native deep-input child did not finish: %s", output)
			}
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || !strings.Contains(string(output), "native-deep-operation="+operation) {
					t.Fatalf("unexpected native child failure: %v: %s", err, output)
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				signaled := ok && status.Signaled() && (status.Signal() == syscall.SIGSEGV || status.Signal() == syscall.SIGABRT)
				cgoFatal := exit.ExitCode() == 2 && strings.Contains(string(output), "SIGSEGV: segmentation violation") && strings.Contains(string(output), "signal arrived during cgo execution")
				if !signaled && !cgoFatal {
					t.Fatalf("unexpected native deep-input failure: %v: %s", err, output)
				}
				t.Logf("native deep input ended its child: %v", err)
			}
		})
	}
	// A failed child must leave the parent process and an ordinary native session usable.
	authorizer, err := testruntime.New(t).NewAuthorizer(context.Background(), authorization.Config{Policies: nestedPolicy(400)})
	if err != nil {
		t.Fatalf("400 nested parentheses: %v", err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(context.Background(), fault.SimpleRequest(request.Context{}))
	if err != nil || response.Decision != request.Allow {
		t.Fatalf("parent authorization after deep-input child: %+v %v", response, err)
	}
}

func TestNativeStackOverflowHelper(t *testing.T) {
	operation := os.Getenv("CGW_NATIVE_STACK_CHILD")
	if operation == "" {
		return
	}
	ctx := context.Background()
	runtime, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx)
	fmt.Fprintln(os.Stderr, "native-deep-operation="+operation)
	switch operation {
	case "load":
		authorizer, failure := runtime.NewAuthorizer(ctx, authorization.Config{Policies: nestedPolicy(10000)})
		err = failure
		if authorizer != nil {
			authorizer.Close()
		}
	case "validate":
		_, err = runtime.Validation().Validate(ctx, schema.SchemaFromCedar(""), nestedPolicy(10000))
	default:
		t.Fatalf("unknown native deep-input operation %q", operation)
	}
	if err != nil {
		var diagnosticError *diagnostic.Error
		if !errors.As(err, &diagnosticError) || (diagnosticError.Kind != diagnostic.KindPolicies && diagnosticError.Kind != diagnostic.KindFault) {
			t.Fatalf("unexpected deep-input error: %v", err)
		}
	}
	authorizer, err := runtime.NewAuthorizer(ctx, authorization.Config{Policies: fault.PermitAll})
	if err != nil {
		t.Fatalf("native runtime did not recover from a returned deep-input result: %v", err)
	}
	authorizer.Close()
}
