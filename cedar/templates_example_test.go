package cedar_test

import (
	"context"
	"fmt"
	"log"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func ExampleRuntime_LinkTemplate() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)

	policies, err := rt.AddTemplate(ctx, cedar.PolicySet{}, "share", cedar.TemplateFromCedar(
		`permit(principal == ?principal, action == Action::"view", resource == ?resource);`))
	if err != nil {
		log.Fatal(err)
	}
	policies, err = rt.LinkTemplate(ctx, policies, "share", "alice-beach", cedar.SlotBindings{
		cedar.PrincipalSlot: cedar.NewEntityUID("User", "alice"),
		cedar.ResourceSlot:  cedar.NewEntityUID("Photo", "beach"),
	})
	if err != nil {
		log.Fatal(err)
	}

	schema := cedar.SchemaFromCedar(`entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {} };`)
	validation, err := rt.Validate(ctx, schema, policies)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid:", validation.Passed)
	authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: policies})
	if err != nil {
		log.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedar.Request{
		Principal: cedar.NewEntityUID("User", "alice"),
		Action:    cedar.NewEntityUID("Action", "view"),
		Resource:  cedar.NewEntityUID("Photo", "beach"),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(response.Decision, response.Reasons)

	policies, err = rt.UnlinkTemplate(ctx, policies, "alice-beach")
	if err != nil {
		log.Fatal(err)
	}
	policies, err = rt.RemoveTemplate(ctx, policies, "share")
	if err != nil {
		log.Fatal(err)
	}
	templates, err := rt.Templates(ctx, policies)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("remaining templates:", len(templates))
	// Output:
	// valid: true
	// allow [alice-beach]
	// remaining templates: 0
}
