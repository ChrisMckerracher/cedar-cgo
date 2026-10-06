package fault

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	strings "strings"
	testing "testing"
)

// A denial under permitAll can only come from the fail-closed path.
var PermitAll = cedarpolicy.PoliciesFromCedar("permit(principal, action, resource);")

func SimpleRequest(ctx request.Context) request.Request {
	return request.Request{
		Principal: entityuid.NewEntityUID("User", "alice"),
		Action:    entityuid.NewEntityUID("Action", "view"),
		Resource:  entityuid.NewEntityUID("Photo", "p1"),
		Context:   ctx,
	}
}

func CheckNoFault(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("module fault: %v", err)
	}
}

func RequireFaultThenRecovery(t *testing.T, a *authorization.Authorizer, resp request.Response, err error, wantStderr string) {
	t.Helper()
	if resp.Decision != request.Deny {
		t.Fatalf("faulted call returned %v, want deny", resp.Decision)
	}
	if !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("got error %v, want a fault", err)
	}
	if wantStderr != "" && !strings.Contains(err.Error(), wantStderr) {
		t.Fatalf("fault %q does not mention %q", err, wantStderr)
	}
	before := a.Stats()
	if before.Discarded != 1 {
		t.Fatalf("stats after fault: %+v, want 1 discarded instance", before)
	}
	resp, err = a.Authorize(context.Background(), SimpleRequest(request.Context{}))
	if err != nil || resp.Decision != request.Allow {
		t.Fatalf("call after fault: %+v, %v; want allow", resp, err)
	}
	if after := a.Stats(); after.Created != before.Created+1 {
		t.Fatalf("call after fault did not create a fresh instance: before %+v, after %+v", before, after)
	}
}
