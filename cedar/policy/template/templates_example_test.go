package template_test

import (
	context "context"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	log "log"
)

func Example_linkTemplate() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)

	policies, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "share", template.TemplateFromCedar(
		`permit(principal == ?principal, action == Action::"view", resource == ?resource);`))
	if err != nil {
		log.Fatal(err)
	}
	policies, err = rt.Templates().LinkTemplate(ctx, policies, "share", "alice-beach", template.SlotBindings{
		template.PrincipalSlot: entityuid.NewEntityUID("User", "alice"),
		template.ResourceSlot:  entityuid.NewEntityUID("Photo", "beach"),
	})
	if err != nil {
		log.Fatal(err)
	}

	schema := cedarschema.SchemaFromCedar(`entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {} };`)
	validation, err := rt.Validation().Validate(ctx, schema, policies)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid:", validation.Passed)
	authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policies})
	if err != nil {
		log.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedarrequest.Request{
		Principal: entityuid.NewEntityUID("User", "alice"),
		Action:    entityuid.NewEntityUID("Action", "view"),
		Resource:  entityuid.NewEntityUID("Photo", "beach"),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(response.Decision, response.Reasons)

	policies, err = rt.Templates().UnlinkTemplate(ctx, policies, "alice-beach")
	if err != nil {
		log.Fatal(err)
	}
	policies, err = rt.Templates().RemoveTemplate(ctx, policies, "share")
	if err != nil {
		log.Fatal(err)
	}
	templates, err := rt.Templates().Templates(ctx, policies)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("remaining templates:", len(templates))
	// Output:
	// valid: true
	// allow [alice-beach]
	// remaining templates: 0
}
