package cedar_test

import (
	"context"
	"testing"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func FuzzPartialEntities(f *testing.F) {
	for _, seed := range []string{
		`[]`, `[`, `null`, `{}`, `[{"uid":{"type":"User","id":"alice"}}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{},"parents":[],"tags":{}}]`,
		`[{"uid":{"type":"User","id":"alice"},"attrs":{"nested":{"__entity":{"type":"User","id":"bob"}}}}]`,
	} {
		f.Add([]byte(seed))
	}
	a := partialAuthorizer(f, cedar.Limits{MaxInstances: 1, MaxRequestBytes: 32 << 10, CallTimeout: fuzzLimits.CallTimeout})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<10 || nesting(string(data)) > 40 {
			t.Skip()
		}
		req := partialRequest()
		req.Entities = cedar.PartialEntitiesFromJSON(data)
		r, err := a.PartialAuthorize(context.Background(), req)
		checkNoFault(t, err)
		if !utf8.Valid(data) {
			requireUTF8InputError(t, err)
			if r.Decision != cedar.Undecided {
				t.Fatalf("malformed input decided: %+v", r)
			}
			return
		}
		if err != nil {
			if r.Decision != cedar.Undecided {
				t.Fatalf("error grants decision: %+v %v", r, err)
			}
			return
		}
		if r.Decision != cedar.Undecided {
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
	a := partialAuthorizer(f, cedar.Limits{MaxInstances: 1, MaxRequestBytes: 32 << 10, CallTimeout: fuzzLimits.CallTimeout})
	f.Fuzz(func(t *testing.T, principalID, resourceID, ctxJSON string) {
		if len(principalID)+len(resourceID)+len(ctxJSON) > 4096 || nesting(ctxJSON) > 40 {
			t.Skip()
		}
		partial, err := a.PartialAuthorize(context.Background(), partialRequest())
		checkNoFault(t, err)
		if err != nil {
			if partial.Decision != cedar.Undecided {
				t.Fatalf("error grants decision: %+v %v", partial, err)
			}
			return
		}
		if partial.Decision != cedar.Undecided {
			t.Fatalf("unknown context unexpectedly decided: %+v", partial)
		}
		concrete := cedar.Request{
			Principal: cedar.NewEntityUID("User", principalID),
			Action:    cedar.NewEntityUID("Action", "view"),
			Resource:  cedar.NewEntityUID("Photo", resourceID),
			Context:   cedar.ContextFromJSON([]byte(ctxJSON)),
		}
		residual, err := partial.Reauthorize(context.Background(), concrete)
		checkNoFault(t, err)
		if !utf8.ValidString(principalID) || !utf8.ValidString(resourceID) || !utf8.ValidString(ctxJSON) {
			requireUTF8InputError(t, err)
			if residual.Decision != cedar.Deny {
				t.Fatalf("malformed input allowed: %+v", residual)
			}
			return
		}
		if err != nil && residual.Decision != cedar.Deny {
			t.Fatalf("error came with %v: %v", residual.Decision, err)
		}
		direct, derr := a.Authorize(context.Background(), concrete)
		checkNoFault(t, derr)
		if derr != nil && direct.Decision != cedar.Deny {
			t.Fatalf("error came with %v: %v", direct.Decision, derr)
		}
		if (err == nil) != (derr == nil) || (err == nil && residual.Decision != direct.Decision) {
			t.Fatalf("reauthorize %v/%v disagrees with direct %v/%v", residual.Decision, err, direct.Decision, derr)
		}
	})
}
