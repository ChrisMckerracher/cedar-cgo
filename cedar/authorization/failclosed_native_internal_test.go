package authorization

import (
	"context"
	"errors"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	"testing"
)

// A permit-all policy makes denial attributable to native fault handling.
func TestFailClosedOnCorruptInstance(t *testing.T) {
	for _, closeHandle := range []bool{false, true} {
		t.Run(map[bool]string{false: "faulted", true: "closed"}[closeHandle], func(t *testing.T) {
			ctx := context.Background()
			rt, err := execution.New(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close(ctx)
			a, err := NewAuthorizer(ctx, rt, Config{
				Policies: policy.PoliciesFromCedar("permit(principal, action, resource);"),
				Limits:   Limits{MaxInstances: 1},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			req := request.Request{Principal: uid.NewEntityUID("User", "alice"), Action: uid.NewEntityUID("Action", "view"), Resource: uid.NewEntityUID("Photo", "p1")}
			if resp, err := a.Authorize(ctx, req); err != nil || resp.Decision != request.Allow {
				t.Fatalf("before fault: %+v, %v", resp, err)
			}
			resource, err := a.session.Pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if closeHandle {
				if err := resource.Value().Close(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				resource.Value().MarkFaulted()
			}
			resource.Release()
			resp, err := a.Authorize(ctx, req)
			if resp.Decision != request.Deny || !errors.Is(err, diagnostic.ErrFault) {
				t.Fatalf("faulted instance: %+v, %v; want deny and a fault", resp, err)
			}
			if stats := a.Stats(); stats.Discarded != 1 || stats.Idle != 0 {
				t.Fatalf("faulted instance was not discarded: %+v", stats)
			}
			if resp, err := a.Authorize(ctx, req); err != nil || resp.Decision != request.Allow {
				t.Fatalf("replacement instance: %+v, %v; want allow", resp, err)
			}
			if stats := a.Stats(); stats.Created != 2 {
				t.Fatalf("stats %+v, want two instances created", stats)
			}
		})
	}
}
