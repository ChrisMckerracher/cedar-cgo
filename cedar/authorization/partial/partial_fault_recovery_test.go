package partial

import (
	"strings"

	context "context"
	errors "errors"

	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	testing "testing"
	time "time"
)

func TestPartialFaultRecovery(t *testing.T) {
	ctx := context.Background()
	rt, err := execution.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {mfa: Bool, payload?: String}};`)
	a, err := newClient(ctx, rt, TestConfig{Schema: &schema, Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa };`), Limits: execution.Limits{MaxInstances: 1, MaxRequestBytes: 8 << 20, CallTimeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.session.Close()
	req := PartialRequest{Principal: UnknownEntityUID("User"), Action: entityuid.NewEntityUID("Action", "view"), Resource: UnknownEntityUID("Photo")}
	continuation, err := a.PartialAuthorize(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	concrete := cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: req.Action, Resource: entityuid.NewEntityUID("Photo", "one"), Context: cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(true)})}
	recover := func(t *testing.T) {
		t.Helper()
		r, err := continuation.Reauthorize(ctx, concrete)
		if err != nil || r.Decision != cedarrequest.Allow {
			t.Fatalf("recovery: %+v %v", r, err)
		}
	}
	t.Run("waiting_cancellation", func(t *testing.T) {
		res, err := a.session.Pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Release()
		for _, resume := range []bool{false, true} {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
			if resume {
				r, e := continuation.Reauthorize(cctx, concrete)
				if r.Decision != cedarrequest.Deny || !errors.Is(e, context.DeadlineExceeded) {
					t.Fatalf("%+v %v", r, e)
				}
			} else {
				r, e := a.PartialAuthorize(cctx, req)
				if r.Decision != Undecided || !errors.Is(e, context.DeadlineExceeded) {
					t.Fatalf("%+v %v", r, e)
				}
			}
			cancel()
		}
	})
	for _, resume := range []bool{false, true} {
		for _, fault := range []string{"response_limit", "corruption", "request_limit"} {
			t.Run(fault+map[bool]string{false: "_partial", true: "_reauthorize"}[resume], func(t *testing.T) {
				before := a.session.Stats().Discarded
				preq, creq := req, concrete
				switch fault {
				case "response_limit":
					rt.MaxResponse = 8
				case "corruption":
					res, err := a.session.Pool.Acquire(ctx)
					if err != nil {
						t.Fatal(err)
					}
					_ = res.Value().Close(ctx)
					res.Release()
				case "request_limit":
					big := cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(true), "payload": cedarvalue.String(strings.Repeat("x", 4<<20))})
					preq.Context, creq.Context = &big, big
					a.session.Limits.MaxRequestBytes = 1024

				}
				if resume {
					r, e := continuation.Reauthorize(ctx, creq)
					if r.Decision != cedarrequest.Deny || !expectedFault(e, fault) {
						t.Fatalf("%+v %v", r, e)
					}
				} else {
					r, e := a.PartialAuthorize(ctx, preq)
					if r.Decision != Undecided || !expectedFault(e, fault) {
						t.Fatalf("%+v %v", r, e)
					}
				}
				rt.MaxResponse = execution.DefaultMaxResponseBytes
				a.session.Limits.MaxRequestBytes = 8 << 20
				expectedDiscard := before + 1
				if fault == "request_limit" {
					expectedDiscard = before
				}
				if a.session.Stats().Discarded != expectedDiscard {
					t.Fatalf("fault retained: %+v", a.session.Stats())
				}
				recover(t)
			})
		}
	}
}

func expectedFault(err error, mode string) bool {
	if mode != "request_limit" {
		return errors.Is(err, diagnostic.ErrFault)
	}
	var ce *diagnostic.Error
	return errors.As(err, &ce) && ce.Kind == diagnostic.KindLimit
}
