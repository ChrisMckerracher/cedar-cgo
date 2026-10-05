package partial_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	rapid "pgregory.net/rapid"
	testing "testing"
)

// Soundness: reauthorizing residuals with a concrete completion equals direct
// authorization of that completion (docs/partial-evaluation.md).
func TestPropertyPartialReauthorizeMatchesDirect(t *testing.T) {
	d := testsupport.LoadJoy(t)
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		TextValue := generator.PropGenPolicySet(2).Draw(pt, "policies")
		generator.PropAssertStrictlyValid(pt, rt, d.Schema, TextValue)
		a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &d.Schema, Policies: cedarpolicy.PoliciesFromCedar(TextValue), Entities: d.Entities})
		if err != nil {
			pt.Fatalf("load: %v\n%s", err, TextValue)
		}
		defer a.Close()
		req := generator.PropGenRequest().Draw(pt, "request")
		partialReq := cedarpartial.PartialRequest{Action: req.Action, Context: nil}
		if rapid.Bool().Draw(pt, "knownPrincipal") {
			partialReq.Principal = cedarpartial.KnownEntityUID(req.Principal)
		} else {
			partialReq.Principal = cedarpartial.UnknownEntityUID("Joy::Device")
		}
		if rapid.Bool().Draw(pt, "knownResource") {
			partialReq.Resource = cedarpartial.KnownEntityUID(req.Resource)
		} else {
			partialReq.Resource = cedarpartial.UnknownEntityUID("Joy::Session")
		}
		res, err := a.Partial().PartialAuthorize(ctx, partialReq)
		if err != nil {
			pt.Fatalf("partial: %v\n%s", err, TextValue)
		}
		exported, err := res.Export()
		if err != nil {
			pt.Fatalf("export: %v", err)
		}
		imported, err := a.Partial().ImportPartialResponse(ctx, exported)
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
		if !generator.PropResponseEqual(resumed, direct) {
			pt.Fatalf("reauthorize differs from direct authorization: %+v vs %+v\n%s", resumed, direct, TextValue)
		}
	})
}

// With no unknown data, partial evaluation decides exactly like full evaluation.
// TPE treats missing entities as unknown, so the request uses stored entities.
func TestPropertyPartialFullyKnownMatchesDirect(t *testing.T) {
	d := testsupport.LoadJoy(t)
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		TextValue := generator.PropGenPolicySet(2).Draw(pt, "policies")
		generator.PropAssertStrictlyValid(pt, rt, d.Schema, TextValue)
		a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &d.Schema, Policies: cedarpolicy.PoliciesFromCedar(TextValue), Entities: d.Entities})
		if err != nil {
			pt.Fatalf("load: %v\n%s", err, TextValue)
		}
		defer a.Close()
		req := generator.PropGenRequest().Draw(pt, "request")
		req.Principal = entityuid.NewEntityUID("Joy::Device", "phone1")
		req.Resource = entityuid.NewEntityUID("Joy::Session", "s1")
		res, err := a.Partial().PartialAuthorize(ctx, cedarpartial.PartialRequest{
			Principal: cedarpartial.KnownEntityUID(req.Principal),
			Action:    req.Action,
			Resource:  cedarpartial.KnownEntityUID(req.Resource),
			Context:   &req.Context,
		})
		if err != nil {
			pt.Fatalf("partial: %v\n%s", err, TextValue)
		}
		direct, err := a.Authorize(ctx, req)
		if err != nil {
			pt.Fatalf("direct: %v", err)
		}
		want := cedarpartial.PartialDeny
		if direct.Decision == cedarrequest.Allow {
			want = cedarpartial.PartialAllow
		}
		if res.Decision != want {
			pt.Fatalf("fully-known partial decided %v, direct authorization %v\n%s", res.Decision, direct.Decision, TextValue)
		}
	})
}
