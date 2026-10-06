package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/internal/execution"
)

func TestAuthorizeCancellationDuringDecode(t *testing.T) {
	background := context.Background()
	runtime, err := execution.New(background)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(background)
	authorizer, err := NewAuthorizer(background, runtime, Config{
		Policies: policy.PoliciesFromCedar("permit(principal, action, resource);"),
		Limits:   Limits{MaxInstances: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	req := request.Request{Principal: uid.NewEntityUID("User", "alice"), Action: uid.NewEntityUID("Action", "view"), Resource: uid.NewEntityUID("Photo", "p1")}
	ctx, cancel := context.WithCancel(background)
	defer cancel()
	decodedAllow := false
	response, err := authorizer.authorize(ctx, req, func(data []byte) (request.Response, error) {
		decoded, decodeErr := request.DecodeAuthorize(data)
		decodedAllow = decodeErr == nil && decoded.Decision == request.Allow && len(decoded.Reasons) != 0
		cancel()
		return decoded, decodeErr
	})
	if !decodedAllow {
		t.Fatal("native response did not permit the request before cancellation")
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("cancellation error: %v", err)
	}
	if response.Decision != request.Deny || response.Reasons != nil || response.Errors != nil {
		t.Fatalf("canceled authorization retained decoded data: %+v", response)
	}
	if stats := authorizer.Stats(); stats.Discarded != 1 || stats.Idle != 0 {
		t.Fatalf("canceled instance returned to the pool: %+v", stats)
	}
	if response, err := authorizer.Authorize(background, req); err != nil || response.Decision != request.Allow {
		t.Fatalf("replacement authorization: %+v, %v", response, err)
	}
	if stats := authorizer.Stats(); stats.Created != 2 {
		t.Fatalf("replacement instance count: %+v", stats)
	}
}
