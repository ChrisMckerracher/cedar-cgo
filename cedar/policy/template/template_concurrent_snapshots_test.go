package template_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	sync "sync"
	testing "testing"
)

func TestTemplateConcurrentSnapshots(t *testing.T) {
	ctx, rt := context.Background(), testruntime.New(t)
	set, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, "share", template.TemplateFromCedar(ShareTemplate))
	if err != nil {
		t.Fatal(err)
	}
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: set})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			linked, err := rt.Templates().LinkTemplate(ctx, set, "share", "same-id", ShareBindings())
			if err != nil {
				t.Error(err)
				return
			}
			links, err := rt.Templates().TemplateLinks(ctx, linked)
			if err != nil || len(links) != 1 {
				t.Errorf("independent link result %v, %v", links, err)
			}
		})
	}
	wg.Wait()
	resp, err := a.Authorize(ctx, TemplateRequest())
	if err != nil || resp.Decision != cedarrequest.Deny {
		t.Fatalf("existing authorizer changed: %+v, %v", resp, err)
	}
}

func TestTemplateRejectsInvalidUTF8(t *testing.T) {
	ctx, rt := context.Background(), testruntime.New(t)
	bad := string([]byte{0xff})
	set := cedarpolicy.PolicySet{}
	calls := []func() error{
		func() error {
			_, err := rt.Templates().AddTemplate(ctx, set, bad, template.TemplateFromCedar(ShareTemplate))
			return err
		},
		func() error {
			_, err := rt.Templates().AddTemplate(ctx, set, "t", template.TemplateFromCedar(bad))
			return err
		},
		func() error { _, err := rt.Templates().Templates(ctx, cedarpolicy.PoliciesFromCedar(bad)); return err },
		func() error { _, err := rt.Templates().LinkTemplate(ctx, set, bad, "p", nil); return err },
		func() error { _, err := rt.Templates().LinkTemplate(ctx, set, "t", bad, nil); return err },
		func() error {
			_, err := rt.Templates().LinkTemplate(ctx, set, "t", "p", template.SlotBindings{template.PrincipalSlot: entityuid.NewEntityUID("User", bad)})
			return err
		},
		func() error {
			_, err := rt.Templates().LinkTemplate(ctx, set, "t", "p", template.SlotBindings{template.PrincipalSlot: entityuid.NewEntityUID(bad, "a")})
			return err
		},
		func() error {
			_, err := rt.Templates().LinkTemplate(ctx, set, "t", "p", template.SlotBindings{template.SlotID(bad): entityuid.NewEntityUID("User", "a")})
			return err
		},
		func() error { _, err := rt.Templates().UnlinkTemplate(ctx, set, bad); return err },
		func() error { _, err := rt.Templates().RemoveTemplate(ctx, set, bad); return err },
	}
	for i, call := range calls {
		var ce *diagnostic.Error
		if err := call(); !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestTemplateDiagnosticIDs(t *testing.T) {
	ctx, rt := context.Background(), testruntime.New(t)
	templateID, policyID := "template\\\"\n\x00雪", "linked\\\"\n\x00雪"
	set, err := rt.Templates().AddTemplate(ctx, cedarpolicy.PolicySet{}, templateID, template.TemplateFromCedar(`permit(principal == ?principal, action, resource) when { context.missing };`))
	if err != nil {
		t.Fatal(err)
	}
	set, err = rt.Templates().LinkTemplate(ctx, set, templateID, policyID, template.SlotBindings{template.PrincipalSlot: entityuid.NewEntityUID("User", "alice")})
	if err != nil {
		t.Fatal(err)
	}
	validation, err := rt.Validation().Validate(ctx, cedarschema.SchemaFromCedar(TemplateSchema), set)
	if err != nil || validation.Passed || len(validation.Errors) == 0 {
		t.Fatalf("invalid context reference: %+v, %v", validation, err)
	}
	for _, message := range validation.Errors {
		if message.PolicyID != templateID && message.PolicyID != policyID {
			t.Fatalf("escaped validation ID %q", message.PolicyID)
		}
	}
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: set})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	result, err := a.Authorize(ctx, TemplateRequest())
	if err != nil || result.Decision != cedarrequest.Deny || len(result.Errors) != 1 || result.Errors[0].PolicyID != policyID {
		t.Fatalf("evaluation diagnostic %+v, %v", result, err)
	}
}
