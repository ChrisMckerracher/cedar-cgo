package integration_test

import (
	context "context"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"

	log "log"
)

func Example() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)

	schema := cedarschema.SchemaFromCedar(PhotoSchema)
	alice := entityuid.NewEntityUID("User", "alice")
	a, err := rt.NewAuthorizer(ctx, authorization.Config{
		Schema:   &schema,
		Policies: cedarpolicy.PoliciesFromCedar(PhotoPolicies),
		Entities: cedarentity.NewEntities(
			cedarentity.Entity{UID: alice},
			cedarentity.Entity{
				UID:   entityuid.NewEntityUID("Photo", "beach"),
				Attrs: cedarvalue.Record{"owner": cedarvalue.EntityRef(alice), "private": cedarvalue.Bool(true)},
			},
		),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	for _, mfa := range []bool{true, false} {
		resp, err := a.Authorize(ctx, cedarrequest.Request{
			Principal: alice,
			Action:    entityuid.NewEntityUID("Action", "view"),
			Resource:  entityuid.NewEntityUID("Photo", "beach"),
			Context:   cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(mfa)}),
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(resp.Decision, resp.Reasons)
	}
	// Output:
	// allow [policy0]
	// deny [policy1]
}

func Example_validate() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)

	res, err := rt.Validation().Validate(ctx, cedarschema.SchemaFromCedar(PhotoSchema),
		cedarpolicy.PoliciesFromCedar(`permit(principal, action, resource) when { resource.owner == "alice" };`))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Passed, len(res.Errors), res.Errors[0].PolicyID)
	// Output: false 1 policy0
}
