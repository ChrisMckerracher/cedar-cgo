package execution_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
)

func TestSessionDeadlineBeforeEntryKeepsInstance(t *testing.T) {
	ctx := context.Background()
	runtime, err := execution.New(ctx, execution.WithMaxConcurrentCalls(1))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx)
	session, err := execution.NewSession(ctx, runtime, []byte(`{"policies":{"format":"cedar","text":"permit(principal, action, resource);"},"entities":[]}`), execution.Limits{MaxInstances: 1, CallTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	release, err := runtime.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"principal":{"type":"User","id":"alice"},"action":{"type":"Action","id":"view"},"resource":{"type":"Photo","id":"p1"},"context":{},"entities":[]}`)
	var response request.Response
	decoded := false
	err = session.Call(ctx, "cgw_authorize", input, func(data []byte) error {
		decoded = true
		var decodeErr error
		response, decodeErr = request.DecodeAuthorize(data)
		return decodeErr
	})
	release()
	if decoded || response.Decision != request.Deny || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("deadline before entry: decoded=%t, response=%+v, error=%v", decoded, response, err)
	}
	if stats := session.Stats(); stats.Created != 1 || stats.Discarded != 0 || stats.Idle != 1 {
		t.Fatalf("deadline before entry changed the healthy pool: %+v", stats)
	}
	session.Limits.CallTimeout = -1
	err = session.Call(ctx, "cgw_authorize", input, func(data []byte) error {
		var decodeErr error
		response, decodeErr = request.DecodeAuthorize(data)
		return decodeErr
	})
	if err != nil || response.Decision != request.Allow {
		t.Fatalf("healthy instance after deadline: %+v, %v", response, err)
	}
	if stats := session.Stats(); stats.Created != 1 || stats.Discarded != 0 || stats.Idle != 1 {
		t.Fatalf("recovery replaced the healthy instance: %+v", stats)
	}
}
