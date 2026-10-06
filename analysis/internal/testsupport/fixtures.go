package testsupport

import (
	"context"
	"fmt"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	requests "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

const Schema = `entity User; entity Document; action view appliesTo { principal: User, resource: Document, context: { n: Long } };`

func Policy(effect, condition string) policy.PolicySet {
	if condition == "" {
		return policy.PoliciesFromCedar(effect + `(principal, action, resource);`)
	}
	return policy.PoliciesFromCedar(fmt.Sprintf(`%s(principal, action, resource) when { %s };`, effect, condition))
}

func Replay(t testing.TB, rt *cedar.Runtime, schema schemas.Schema, policy policy.PolicySet, request requests.Request) requests.Response {
	t.Helper()
	authorizer, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: &schema, Policies: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	result, err := authorizer.Authorize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
