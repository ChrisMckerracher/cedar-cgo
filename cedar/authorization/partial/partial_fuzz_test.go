package partial_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	partialinput "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial/input"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"
	partialfixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/partial"

	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzPartialEntities(f *testing.F) {
	for _, seed := range []string{
		`[]`, `[`, `null`, `{}`, `[{"uid":{"type":"User","id":"alice"}}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{},"parents":[],"tags":{}}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{"nested":{"__entity":{"type":"User","id":"bob"}}}}]`,
	} {
		f.Add([]byte(seed))
	}
	a := partialfixture.PartialAuthorizer(f, authorization.Limits{MaxInstances: 1, MaxRequestBytes: 32 << 10, CallTimeout: fuzz.FuzzLimits.CallTimeout})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<10 || fuzz.Nesting(string(data)) > 40 {
			t.Skip()
		}
		req := partialfixture.PartialRequest()
		req.Entities = partialinput.PartialEntitiesFromJSON(data)
		r, err := a.Partial().PartialAuthorize(context.Background(), req)
		fault.CheckNoFault(t, err)
		if !utf8.Valid(data) {
			fault.RequireUTF8InputError(t, err)
			if r.Decision != cedarpartial.Undecided {
				t.Fatalf("malformed input decided: %+v", r)
			}
			return
		}
		if err != nil {
			if r.Decision != cedarpartial.Undecided {
				t.Fatalf("error grants decision: %+v %v", r, err)
			}
			return
		}
		if r.Decision != cedarpartial.Undecided {
			t.Fatalf("unknown MFA unexpectedly decided: %+v", r)
		}
	})
}

// FuzzPartialReauthorize checks the core TPE soundness contract: authorizing
// the residual with concrete values must equal direct authorization with the
// same values, because reauthorization replays the frozen partial input.
func FuzzPartialReauthorize(f *testing.F) {
	f.Add("alice", "beach", `{"mfa":true}`)
	f.Add("alice", "beach", `{"mfa":false}`)
	f.Add("", "", `{`)
	f.Add("alice", "beach", `{"mfa":"yes"}`)
	f.Add("a\n\"雪\x00", "b", `{"mfa":{"nested":true}}`)
	a := partialfixture.PartialAuthorizer(f, authorization.Limits{MaxInstances: 1, MaxRequestBytes: 32 << 10, CallTimeout: fuzz.FuzzLimits.CallTimeout})
	f.Fuzz(func(t *testing.T, principalID, resourceID, ctxJSON string) {
		if len(principalID)+len(resourceID)+len(ctxJSON) > 4096 || fuzz.Nesting(ctxJSON) > 40 {
			t.Skip()
		}
		partial, err := a.Partial().PartialAuthorize(context.Background(), partialfixture.PartialRequest())
		fault.CheckNoFault(t, err)
		if err != nil {
			if partial.Decision != cedarpartial.Undecided {
				t.Fatalf("error grants decision: %+v %v", partial, err)
			}
			return
		}
		if partial.Decision != cedarpartial.Undecided {
			t.Fatalf("unknown context unexpectedly decided: %+v", partial)
		}
		concrete := cedarrequest.Request{
			Principal: entityuid.NewEntityUID("User", principalID),
			Action:    entityuid.NewEntityUID("Action", "view"),
			Resource:  entityuid.NewEntityUID("Photo", resourceID),
			Context:   cedarrequest.ContextFromJSON([]byte(ctxJSON)),
		}
		residual, err := partial.Reauthorize(context.Background(), concrete)
		fault.CheckNoFault(t, err)
		if !utf8.ValidString(principalID) || !utf8.ValidString(resourceID) || !utf8.ValidString(ctxJSON) {
			fault.RequireUTF8InputError(t, err)
			if residual.Decision != cedarrequest.Deny {
				t.Fatalf("malformed input allowed: %+v", residual)
			}
			return
		}
		if err != nil && residual.Decision != cedarrequest.Deny {
			t.Fatalf("error came with %v: %v", residual.Decision, err)
		}
		direct, derr := a.Authorize(context.Background(), concrete)
		fault.CheckNoFault(t, derr)
		if derr != nil && direct.Decision != cedarrequest.Deny {
			t.Fatalf("error came with %v: %v", direct.Decision, derr)
		}
		if (err == nil) != (derr == nil) || (err == nil && residual.Decision != direct.Decision) {
			t.Fatalf("reauthorize %v/%v disagrees with direct %v/%v", residual.Decision, err, direct.Decision, derr)
		}
	})
}
