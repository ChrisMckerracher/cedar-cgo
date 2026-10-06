package partial_test

import (
	context "context"
	errors "errors"
	fmt "fmt"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	partialinput "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial/input"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	partialfixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/partial"

	strings "strings"
	testing "testing"
	time "time"
)

func TestPartialExecutionTimeout(t *testing.T) {
	a := partialfixture.PartialAuthorizer(t, authorization.Limits{MaxInstances: 1, CallTimeout: 20 * time.Millisecond, MaxRequestBytes: 8 << 20})
	req := partialfixture.PartialRequest()
	var data strings.Builder
	data.WriteByte('[')
	for i := range 10000 {
		if i > 0 {
			data.WriteByte(',')
		}
		fmt.Fprintf(&data, `{"uid":{"type":"User","id":"%d"},"attrs":{},"parents":[],"tags":{}}`, i)
	}
	data.WriteByte(']')
	req.Entities = partialinput.PartialEntitiesFromJSON([]byte(data.String()))
	start := time.Now()
	r, err := a.Partial().PartialAuthorize(context.Background(), req)
	if r.Decision != cedarpartial.Undecided || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("%+v %v", r, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation failed to bound execution")
	}
	if a.Stats().Discarded != 1 {
		t.Fatalf("faulted instance retained: %+v", a.Stats())
	}
	r, err = a.Partial().PartialAuthorize(context.Background(), partialfixture.PartialRequest())
	if err != nil || r.Decision != cedarpartial.Undecided {
		t.Fatalf("recovery: %+v %v", r, err)
	}
	concrete := fault.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(true)}))
	concrete.Entities = cedarentity.EntitiesFromJSON([]byte(data.String()))
	resp, err := r.Reauthorize(context.Background(), concrete)
	if resp.Decision != cedarrequest.Deny || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reauthorize timeout: %+v %v", resp, err)
	}
	if a.Stats().Discarded != 2 {
		t.Fatalf("reauthorize retained fault: %+v", a.Stats())
	}
	concrete.Entities = cedarentity.Entities{}
	resp, err = r.Reauthorize(context.Background(), concrete)
	if err != nil || resp.Decision != cedarrequest.Allow {
		t.Fatalf("reauthorize recovery: %+v %v", resp, err)
	}
}
