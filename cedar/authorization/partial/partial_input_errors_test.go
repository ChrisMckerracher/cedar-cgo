package partial_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"

	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	strings "strings"

	testing "testing"
)

func TestPartialInputErrors(t *testing.T) {
	a := testsupport.PartialAuthorizer(t, authorization.Limits{MaxRequestBytes: 1024})
	for name, data := range map[string]string{"malformed": "[", "wrong_shape": "{}", "wrong_type": `[{"uid":{"type":"Photo","id":"one"},"parents":false}]`} {
		t.Run(name, func(t *testing.T) {
			req := testsupport.PartialRequest()
			req.Entities = cedarpartial.PartialEntitiesFromJSON([]byte(data))
			r, err := a.Partial().PartialAuthorize(context.Background(), req)
			if err == nil || r.Decision != cedarpartial.Undecided {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	req := testsupport.PartialRequest()
	req.Principal.Type = strings.Repeat("x", 2048)
	r, err := a.Partial().PartialAuthorize(context.Background(), req)
	testsupport.RequirePartialError(t, r, err, diagnostic.KindLimit)
	r, err = a.Partial().PartialAuthorize(context.Background(), testsupport.PartialRequest())
	if err != nil {
		t.Fatal(err)
	}
	c := testsupport.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(true), "big": cedarvalue.String(strings.Repeat("x", 2048))}))
	resp, err := r.Reauthorize(context.Background(), c)
	var ce *diagnostic.Error
	if resp.Decision != cedarrequest.Deny || !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit {
		t.Fatalf("%+v %v", resp, err)
	}
	resp, err = (cedarpartial.PartialResponse{}).Reauthorize(context.Background(), c)
	if resp.Decision != cedarrequest.Deny || err == nil {
		t.Fatalf("zero continuation: %+v %v", resp, err)
	}
	without, err := testsupport.TestRuntime(t).NewAuthorizer(context.Background(), authorization.Config{Policies: testsupport.PermitAll})
	if err != nil {
		t.Fatal(err)
	}
	defer without.Close()
	r, err = without.Partial().PartialAuthorize(context.Background(), testsupport.PartialRequest())
	testsupport.RequirePartialError(t, r, err, diagnostic.KindSchema)
}

func TestPartialCancellationAndClose(t *testing.T) {
	a := testsupport.PartialAuthorizer(t, authorization.Limits{MaxInstances: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := a.Partial().PartialAuthorize(ctx, testsupport.PartialRequest())
	if r.Decision != cedarpartial.Undecided || !errors.Is(err, context.Canceled) {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = a.Partial().PartialAuthorize(context.Background(), testsupport.PartialRequest())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Reauthorize(ctx, testsupport.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(true)})))
	if resp.Decision != cedarrequest.Deny || !errors.Is(err, context.Canceled) {
		t.Fatalf("%+v %v", resp, err)
	}
	a.Close()
	resp, err = r.Reauthorize(context.Background(), testsupport.SimpleRequest(cedarrequest.Context{}))
	if resp.Decision != cedarrequest.Deny || err == nil {
		t.Fatalf("closed: %+v %v", resp, err)
	}
}
