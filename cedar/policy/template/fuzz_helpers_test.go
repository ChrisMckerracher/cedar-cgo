package template_test

import (
	context "context"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	fuzz "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fuzz"
	testing "testing"
)

// EST form of shareTemplate from the native parity fixtures, for the JSON leg.
const FuzzTemplateJSON = `{"effect":"permit","principal":{"op":"==","slot":"?principal"},"action":{"op":"==","entity":{"id":"view","type":"Action"}},"resource":{"op":"==","slot":"?resource"},"annotations":{"description":"shared access"},"conditions":[]}`

// fuzzTemplateDecision authorizes a fixed request against set; errors must deny.
func fuzzTemplateDecision(t *testing.T, rt *cedar.Runtime, set cedarpolicy.PolicySet) (request.Decision, error) {
	t.Helper()
	a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Policies: set, Limits: fuzz.FuzzLimits})
	if err != nil {
		fault.CheckNoFault(t, err)
		return request.Deny, err
	}
	defer a.Close()
	resp, err := a.Authorize(context.Background(), TemplateRequest())
	fault.CheckNoFault(t, err)
	if err != nil && resp.Decision != request.Deny {
		t.Fatalf("error %v came with %v", err, resp.Decision)
	}
	return resp.Decision, nil
}
