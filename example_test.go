package cedar_test

import (
	"context"
	"fmt"
	"log"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm"
)

const photoSchema = `
entity User in [Group];
entity Group;
entity Photo { owner: User, private: Bool };
action view appliesTo { principal: User, resource: Photo, context: { mfa: Bool } };
`

const photoPolicies = `
permit(principal, action == Action::"view", resource)
when { resource.owner == principal || !resource.private };

forbid(principal, action, resource)
unless { context.mfa };
`

func Example() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)

	schema := cedar.SchemaFromCedar(photoSchema)
	alice := cedar.NewEntityUID("User", "alice")
	a, err := rt.NewAuthorizer(ctx, cedar.Config{
		Schema:   &schema,
		Policies: cedar.PoliciesFromCedar(photoPolicies),
		Entities: cedar.NewEntities(
			cedar.Entity{UID: alice},
			cedar.Entity{
				UID:   cedar.NewEntityUID("Photo", "beach"),
				Attrs: cedar.Record{"owner": alice, "private": cedar.Bool(true)},
			},
		),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	for _, mfa := range []bool{true, false} {
		resp, err := a.Authorize(ctx, cedar.Request{
			Principal: alice,
			Action:    cedar.NewEntityUID("Action", "view"),
			Resource:  cedar.NewEntityUID("Photo", "beach"),
			Context:   cedar.NewContext(cedar.Record{"mfa": cedar.Bool(mfa)}),
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

func ExampleRuntime_Validate() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)

	res, err := rt.Validate(ctx, cedar.SchemaFromCedar(photoSchema),
		cedar.PoliciesFromCedar(`permit(principal, action, resource) when { resource.owner == "alice" };`))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Passed, len(res.Errors), res.Errors[0].PolicyID)
	// Output: false 1 policy0
}
