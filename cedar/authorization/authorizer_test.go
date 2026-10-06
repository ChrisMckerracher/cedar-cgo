package authorization_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	joy "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	testing "testing"
)

func TestAuthorizeJoy(t *testing.T) {
	a := joy.NewJoyAuthorizer(t, authorization.Limits{})
	resp, err := a.Authorize(context.Background(), joy.JoyRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != cedarrequest.Allow || len(resp.Reasons) != 1 || resp.Reasons[0] != "policy1" {
		t.Fatalf("got %+v, want allow by policy1", resp)
	}

	req := joy.JoyRequest()
	req.Action = entityuid.NewEntityUID("Joy::Action", "terminal.open")
	resp, err = a.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != cedarrequest.Deny {
		t.Fatalf("terminal.open at device level 1: got %+v, want deny", resp)
	}
}

func TestAuthorizeRequestEntities(t *testing.T) {
	a := joy.NewJoyAuthorizer(t, authorization.Limits{})
	req := joy.JoyRequest()
	req.Principal = entityuid.NewEntityUID("Joy::Device", "tablet9")
	resp, err := a.Authorize(context.Background(), req)
	if err != nil || resp.Decision != cedarrequest.Deny {
		t.Fatalf("unknown device: got %+v, %v; want deny", resp, err)
	}
	req.Entities = cedarentity.NewEntities(cedarentity.Entity{
		UID:     req.Principal,
		Parents: []entityuid.EntityUID{entityuid.NewEntityUID("Joy::Account", "acct1")},
	})
	resp, err = a.Authorize(context.Background(), req)
	if err != nil || resp.Decision != cedarrequest.Allow {
		t.Fatalf("device added for the request: got %+v, %v; want allow", resp, err)
	}
}

func TestAuthorizeErrorsDeny(t *testing.T) {
	a := joy.NewJoyAuthorizer(t, authorization.Limits{})
	cases := map[string]struct {
		mutate func(*cedarrequest.Request)
		kind   diagnostic.ErrorKind
	}{
		"context type": {func(r *cedarrequest.Request) {
			r.Context = cedarrequest.NewContext(cedarvalue.Record{"deviceLevel": cedarvalue.String("high")})
		}, diagnostic.KindContext},
		"undeclared action": {func(r *cedarrequest.Request) {
			r.Action = entityuid.NewEntityUID("Joy::Action", "nope")
		}, diagnostic.KindContext},
		"principal type": {func(r *cedarrequest.Request) {
			r.Principal = entityuid.NewEntityUID("Joy::Session", "s1")
		}, diagnostic.KindRequest},
		"bad type name": {func(r *cedarrequest.Request) {
			r.Principal = entityuid.NewEntityUID("not a name", "x")
		}, diagnostic.KindPrincipal},
		"invalid context JSON": {func(r *cedarrequest.Request) {
			r.Context = cedarrequest.ContextFromJSON([]byte(`{"deviceLevel":`))
		}, diagnostic.KindInput},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := joy.JoyRequest()
			c.mutate(&req)
			resp, err := a.Authorize(context.Background(), req)
			if resp.Decision != cedarrequest.Deny {
				t.Fatalf("got %v, want deny", resp.Decision)
			}
			var cerr *diagnostic.Error
			if !errors.As(err, &cerr) || cerr.Kind != c.kind {
				t.Fatalf("got error %v, want kind %s", err, c.kind)
			}
		})
	}
	if s := a.Stats(); s.Discarded != 0 {
		t.Fatalf("Cedar input errors discarded %d instances, want 0", s.Discarded)
	}
}

func TestNewAuthorizerRejectsBadPolicies(t *testing.T) {
	_, err := testruntime.New(t).NewAuthorizer(context.Background(), authorization.Config{
		Policies: cedarpolicy.PoliciesFromCedar("permit(principal, action, resource) when { 1 + };"),
	})
	var cerr *diagnostic.Error
	if !errors.As(err, &cerr) || cerr.Kind != diagnostic.KindPolicies {
		t.Fatalf("got %v, want a policies error", err)
	}
}

func TestValidate(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	res, err := rt.Validation().Validate(context.Background(), d.Schema, d.Old)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Fatalf("joy policies failed strict validation: %+v", res.Errors)
	}
	res, err = rt.Validation().Validate(context.Background(), d.Schema,
		cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { context.deviceLevel == "high" };`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed || len(res.Errors) == 0 || res.Errors[0].PolicyID != "policy0" {
		t.Fatalf("type error passed strict validation: %+v", res)
	}
}
