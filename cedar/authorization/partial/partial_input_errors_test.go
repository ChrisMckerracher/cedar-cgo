package partial_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	partialinput "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial/input"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	partialfixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/partial"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"

	strings "strings"

	testing "testing"
)

func TestPartialInputErrors(t *testing.T) {
	a := partialfixture.PartialAuthorizer(t, authorization.Limits{MaxRequestBytes: 1024})
	for name, data := range map[string]string{"malformed": "[", "wrong_shape": "{}", "wrong_type": `[{"uid":{"type":"Photo","id":"one"},"parents":false}]`} {
		t.Run(name, func(t *testing.T) {
			req := partialfixture.PartialRequest()
			req.Entities = partialinput.PartialEntitiesFromJSON([]byte(data))
			r, err := a.Partial().PartialAuthorize(context.Background(), req)
			if err == nil || r.Decision != cedarpartial.Undecided {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	req := partialfixture.PartialRequest()
	req.Principal.Type = strings.Repeat("x", 2048)
	r, err := a.Partial().PartialAuthorize(context.Background(), req)
	partialfixture.RequirePartialError(t, r, err, diagnostic.KindLimit)
	r, err = a.Partial().PartialAuthorize(context.Background(), partialfixture.PartialRequest())
	if err != nil {
		t.Fatal(err)
	}
	c := fault.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(true), "big": cedarvalue.String(strings.Repeat("x", 2048))}))
	resp, err := r.Reauthorize(context.Background(), c)
	var ce *diagnostic.Error
	if resp.Decision != cedarrequest.Deny || !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit {
		t.Fatalf("%+v %v", resp, err)
	}
	resp, err = (cedarpartial.PartialResponse{}).Reauthorize(context.Background(), c)
	if resp.Decision != cedarrequest.Deny || err == nil {
		t.Fatalf("zero continuation: %+v %v", resp, err)
	}
	without, err := testruntime.New(t).NewAuthorizer(context.Background(), authorization.Config{Policies: fault.PermitAll})
	if err != nil {
		t.Fatal(err)
	}
	defer without.Close()
	r, err = without.Partial().PartialAuthorize(context.Background(), partialfixture.PartialRequest())
	partialfixture.RequirePartialError(t, r, err, diagnostic.KindSchema)
}

func TestPartialCancellationAndClose(t *testing.T) {
	a := partialfixture.PartialAuthorizer(t, authorization.Limits{MaxInstances: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := a.Partial().PartialAuthorize(ctx, partialfixture.PartialRequest())
	if r.Decision != cedarpartial.Undecided || !errors.Is(err, context.Canceled) {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = a.Partial().PartialAuthorize(context.Background(), partialfixture.PartialRequest())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Reauthorize(ctx, fault.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(true)})))
	if resp.Decision != cedarrequest.Deny || !errors.Is(err, context.Canceled) {
		t.Fatalf("%+v %v", resp, err)
	}
	a.Close()
	resp, err = r.Reauthorize(context.Background(), fault.SimpleRequest(cedarrequest.Context{}))
	if resp.Decision != cedarrequest.Deny || err == nil {
		t.Fatalf("closed: %+v %v", resp, err)
	}
}
