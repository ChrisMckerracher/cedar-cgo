package template_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
)

func TestTemplateNativeParity(t *testing.T) {
	var fixtures struct {
		CedarVersion string `json:"cedar_version"`
		Schema       string
		Cases        []struct {
			Name      string
			Policies  json.RawMessage
			Operation struct {
				Op         string
				ID         string
				TemplateID string `json:"template_id"`
				PolicyID   string `json:"policy_id"`
				Template   string
				Bindings   map[template.SlotID]struct{ Type, ID string }
			}
			Expected struct {
				Error    string
				Policies json.RawMessage
				Decision string
				Reasons  []string
				Valid    bool
				Errors   []diagnostic.PolicyMessage
				Warnings []diagnostic.PolicyMessage
			}
		}
	}
	if err := json.Unmarshal(testsupport.ReadFile(t, "../testdata/parity/templates/native.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.CedarVersion != "4.13.0" || len(fixtures.Cases) < 20 {
		t.Fatal("missing pinned native template fixtures")
	}
	ctx, rt := context.Background(), testsupport.TestRuntime(t)
	for _, tc := range fixtures.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			before := cedarpolicy.PoliciesFromJSON(tc.Policies)
			op := tc.Operation
			var got cedarpolicy.PolicySet
			var err error
			switch op.Op {
			case "add":
				got, err = rt.Templates().AddTemplate(ctx, before, op.ID, template.TemplateFromCedar(op.Template))
			case "link":
				bindings := make(template.SlotBindings)
				for slot, uid := range op.Bindings {
					bindings[slot] = entityuid.NewEntityUID(uid.Type, uid.ID)
				}
				got, err = rt.Templates().LinkTemplate(ctx, before, op.TemplateID, op.PolicyID, bindings)
			case "unlink":
				got, err = rt.Templates().UnlinkTemplate(ctx, before, op.PolicyID)
			case "remove":
				got, err = rt.Templates().RemoveTemplate(ctx, before, op.TemplateID)
			default:
				t.Fatalf("unknown fixture operation %q", op.Op)
			}
			if tc.Expected.Error != "" {
				var ce *diagnostic.Error
				if !errors.As(err, &ce) || ce.Kind != diagnostic.KindPolicies || ce.Message != tc.Expected.Error {
					t.Fatalf("got %v; native Rust error: %s", err, tc.Expected.Error)
				}
				if got.Text() != "" || before.Text() != string(tc.Policies) {
					t.Fatal("failed operation returned a result or changed the source")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(testsupport.NormalizedPolicyJSON(t, []byte(got.Text())), testsupport.NormalizedPolicyJSON(t, tc.Expected.Policies)) {
				t.Fatalf("Go result %s differs from native Rust %s", got.Text(), tc.Expected.Policies)
			}
			schema := cedarschema.SchemaFromCedar(fixtures.Schema)
			validation, err := rt.Validation().Validate(ctx, schema, got)
			if err != nil || validation.Passed != tc.Expected.Valid || !testsupport.EqualTemplateMessages(validation.Errors, tc.Expected.Errors) || !testsupport.EqualTemplateMessages(validation.Warnings, tc.Expected.Warnings) {
				t.Fatalf("validation %+v, %v; native passed=%v", validation, err, tc.Expected.Valid)
			}
			a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: got})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			response, err := a.Authorize(ctx, testsupport.TemplateRequest())
			if err != nil || response.Decision.String() != tc.Expected.Decision || !reflect.DeepEqual(response.Reasons, tc.Expected.Reasons) || len(response.Errors) != 0 {
				t.Fatalf("authorization %+v, %v; native %s %v", response, err, tc.Expected.Decision, tc.Expected.Reasons)
			}
		})
	}
}
