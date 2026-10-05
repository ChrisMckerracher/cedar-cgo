package policy_test

import (
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"

	context "context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	rapid "pgregory.net/rapid"
	testing "testing"
)

func TestPropertyPSTMappedSetPreservesAuthorization(t *testing.T) {
	d := testsupport.LoadJoy(t)
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		source := cedarpolicy.PoliciesFromCedar(generator.PropGenPolicySet(2).Draw(pt, "policies"))
		parsed, err := rt.Policies().ParsePolicySet(ctx, source)
		if err != nil {
			pt.Fatal(err)
		}
		req := generator.PropGenRequest().Draw(pt, "request")
		var responses []cedarrequest.Response
		for _, source := range []cedarpolicy.PolicySet{source, parsed.Source()} {
			a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &d.Schema, Policies: source, Entities: d.Entities})
			if err != nil {
				pt.Fatal(err)
			}
			response, err := a.Authorize(ctx, req)
			a.Close()
			if err != nil {
				pt.Fatal(err)
			}
			responses = append(responses, response)
		}
		if !generator.PropResponseEqual(responses[0], responses[1]) {
			pt.Fatalf("EST roundtrip changed authorization: %+v", responses)
		}
	})
}
