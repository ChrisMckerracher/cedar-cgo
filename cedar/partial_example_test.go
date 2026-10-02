package cedar_test

import (
	"context"
	"fmt"
	"log"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func ExamplePartialResponse_Reauthorize() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	schema := cedar.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {mfa: Bool}};`)
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema,
		Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource) when { context.mfa };`),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	partial, err := a.PartialAuthorize(ctx, cedar.PartialRequest{
		Principal: cedar.UnknownEntityUID("User"),
		Action:    cedar.NewEntityUID("Action", "view"),
		Resource:  cedar.UnknownEntityUID("Photo"),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(partial.Decision)
	fmt.Println(partial.Residuals[0].PolicyID, partial.Residuals[0].State)
	for _, mfa := range []bool{true, false} {
		response, err := partial.Reauthorize(ctx, cedar.Request{
			Principal: cedar.NewEntityUID("User", "alice"),
			Action:    cedar.NewEntityUID("Action", "view"),
			Resource:  cedar.NewEntityUID("Photo", "beach"),
			Context:   cedar.NewContext(cedar.Record{"mfa": cedar.Bool(mfa)}),
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
