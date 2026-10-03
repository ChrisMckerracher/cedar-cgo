package cedar_test

import (
	"context"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// Soundness: reauthorizing residuals with a concrete completion equals direct
// authorization of that completion (docs/partial-evaluation.md).
func TestPropertyPartialReauthorizeMatchesDirect(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		text := propGenPolicySet(2).Draw(pt, "policies")
		propAssertStrictlyValid(pt, rt, d.schema, text)
		a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: cedar.PoliciesFromCedar(text), Entities: d.entities})
		if err != nil {
			pt.Fatalf("load: %v\n%s", err, text)
		}
		defer a.Close()
		req := propGenRequest().Draw(pt, "request")
		partialReq := cedar.PartialRequest{Action: req.Action, Context: nil}
		if rapid.Bool().Draw(pt, "knownPrincipal") {
			partialReq.Principal = cedar.KnownEntityUID(req.Principal)
		} else {
			partialReq.Principal = cedar.UnknownEntityUID("Joy::Device")
		}
		if rapid.Bool().Draw(pt, "knownResource") {
			partialReq.Resource = cedar.KnownEntityUID(req.Resource)
		} else {
			partialReq.Resource = cedar.UnknownEntityUID("Joy::Session")
		}
		res, err := a.PartialAuthorize(ctx, partialReq)
		if err != nil {
			pt.Fatalf("partial: %v\n%s", err, text)
		}
		exported, err := res.Export()
		if err != nil {
			pt.Fatalf("export: %v", err)
		}
		imported, err := a.ImportPartialResponse(ctx, exported)
		if err != nil {
			pt.Fatalf("import: %v", err)
		}
		resumed, err := imported.Reauthorize(ctx, req)
		if err != nil {
			pt.Fatalf("reauthorize: %v", err)
		}
		direct, err := a.Authorize(ctx, req)
		if err != nil {
			pt.Fatalf("direct: %v", err)
		}
		if !propResponseEqual(resumed, direct) {
			pt.Fatalf("reauthorize differs from direct authorization: %+v vs %+v\n%s", resumed, direct, text)
		}
	})
}

// With no unknown data, partial evaluation decides exactly like full evaluation.
// TPE treats missing entities as unknown, so the request uses stored entities.
func TestPropertyPartialFullyKnownMatchesDirect(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		text := propGenPolicySet(2).Draw(pt, "policies")
		propAssertStrictlyValid(pt, rt, d.schema, text)
		a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &d.schema, Policies: cedar.PoliciesFromCedar(text), Entities: d.entities})
		if err != nil {
			pt.Fatalf("load: %v\n%s", err, text)
		}
		defer a.Close()
		req := propGenRequest().Draw(pt, "request")
		req.Principal = cedar.NewEntityUID("Joy::Device", "phone1")
		req.Resource = cedar.NewEntityUID("Joy::Session", "s1")
		res, err := a.PartialAuthorize(ctx, cedar.PartialRequest{
			Principal: cedar.KnownEntityUID(req.Principal),
			Action:    req.Action,
			Resource:  cedar.KnownEntityUID(req.Resource),
			Context:   &req.Context,
		})
		if err != nil {
			pt.Fatalf("partial: %v\n%s", err, text)
		}
		direct, err := a.Authorize(ctx, req)
		if err != nil {
			pt.Fatalf("direct: %v", err)
		}
		want := cedar.PartialDeny
		if direct.Decision == cedar.Allow {
			want = cedar.PartialAllow
		}
		if res.Decision != want {
			pt.Fatalf("fully-known partial decided %v, direct authorization %v\n%s", res.Decision, direct.Decision, text)
		}
	})
}
