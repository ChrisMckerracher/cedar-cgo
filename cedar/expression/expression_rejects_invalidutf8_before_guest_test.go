package expression

import (
	context "context"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"
	testing "testing"
)

func TestExpressionRejectsInvalidUTF8BeforeGuest(t *testing.T) {
	rt := &Client{runtime: &execution.Runtime{MaxSourceBytes: execution.DefaultMaxSourceBytes}}
	bad := string([]byte{0xff})
	uid := entityuid.NewEntityUID("User", bad)
	for _, env := range []ExpressionEnv{
		{Principal: &uid}, {Action: &uid}, {Resource: &uid},
		{Context: cedarrequest.NewContext(cedarvalue.Record{bad: cedarvalue.Bool(true)})},
		{Context: cedarrequest.NewContext(cedarvalue.Record{"a": cedarvalue.String(bad)})},
		{Context: cedarrequest.ContextFromJSON([]byte(`{"a":"` + bad + `"}`))},
		{Entities: cedarentity.NewEntities(cedarentity.Entity{UID: uid})},
		{Entities: cedarentity.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))},
	} {
		result, err := rt.EvalExpression(context.Background(), Expression{text: "true", valid: true}, env)
		var ce *diagnostic.Error
		if result != nil || !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
			t.Fatalf("malformed environment: %#v %v", result, err)
		}
	}
}
