package partial_test

import (
	context "context"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	log "log"
)

func ExamplePartialResponse_Reauthorize() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {mfa: Bool}};`)
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema,
		Policies: cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa };`),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	partial, err := a.Partial().PartialAuthorize(ctx, cedarpartial.PartialRequest{
		Principal: cedarpartial.UnknownEntityUID("User"),
		Action:    entityuid.NewEntityUID("Action", "view"),
		Resource:  cedarpartial.UnknownEntityUID("Photo"),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(partial.Decision)
	fmt.Println(partial.Residuals[0].PolicyID, partial.Residuals[0].State)
	for _, mfa := range []bool{true, false} {
		response, err := partial.Reauthorize(ctx, cedarrequest.Request{
			Principal: entityuid.NewEntityUID("User", "alice"),
			Action:    entityuid.NewEntityUID("Action", "view"),
			Resource:  entityuid.NewEntityUID("Photo", "beach"),
			Context:   cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(mfa)}),
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(response.Decision)
	}
	// Output:
	// undecided
	// policy0 residual
	// allow
	// deny
}
