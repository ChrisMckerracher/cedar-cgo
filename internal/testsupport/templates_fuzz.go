package testsupport

import (
	context "context"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testing "testing"
)

// EST form of shareTemplate from the native parity fixtures, for the JSON leg.
const FuzzTemplateJSON = `{"effect":"permit","principal":{"op":"==","slot":"?principal"},"action":{"op":"==","entity":{"id":"view","type":"Action"}},"resource":{"op":"==","slot":"?resource"},"annotations":{"description":"shared access"},"conditions":[]}`

// fuzzTemplateDecision authorizes a fixed request against set; errors must deny.
func FuzzTemplateDecision(t *testing.T, rt *cedar.Runtime, set cedarpolicy.PolicySet) (request.Decision, error) {
	t.Helper()
	a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Policies: set, Limits: FuzzLimits})
	if err != nil {
		CheckNoFault(t, err)
		return request.Deny, err
	}
	defer a.Close()
	resp, err := a.Authorize(context.Background(), TemplateRequest())
	CheckNoFault(t, err)
	if err != nil && resp.Decision != request.Deny {
		t.Fatalf("error %v came with %v", err, resp.Decision)
	}
	return resp.Decision, nil
}
