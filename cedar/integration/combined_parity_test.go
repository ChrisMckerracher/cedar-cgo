package integration_test

import (
	context "context"
	json "encoding/json"
	partialinput "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial/input"
	policysupport "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/policy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"

	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"

	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"

	testing "testing"
)

func TestCombinedPolicyEvaluationPaths(t *testing.T) {
	ctx, rt := context.Background(), testruntime.New(t)
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	const suffix = "\"\n\\雪"
	const permitID, templateID, linkedID = "permit" + suffix, "template" + suffix, "linked" + suffix
	principal, resource := entityuid.NewEntityUID("User", "alice"+suffix), entityuid.NewEntityUID("Document", "one"+suffix)
	action := entityuid.NewEntityUID("Action", "read")
	schema := cedarschema.SchemaFromCedar(`entity User { active: Bool }; entity Document { public: Bool }; action read appliesTo { principal: User, resource: Document, context: { mfa: Bool } };`)

	formatted, err := rt.Formatter().FormatPolicies(ctx, `@owner("integration") permit(principal is User,action==Action::"read",resource is Document)when{principal.active&&resource.public};`)
	require(err)
	policy, err := rt.Policies().ParsePolicy(ctx, permitID, formatted)
	require(err)
	document := policysupport.MustPolicyJSON(t, policy)
	document["annotations"].(map[string]any)["stage"] = "json"
	encoded, err := json.Marshal(document)
	require(err)
	policy, err = rt.Policies().PolicyFromJSON(ctx, policy.ID(), encoded)
	require(err)
	if policy.ID() != permitID || policy.Effect() != cedarpolicy.Permit {
		t.Fatalf("JSON reconstruction changed identity/effect: %q %s", policy.ID(), policy.Effect())
	}
	parsed, err := rt.Policies().AddPolicy(ctx, cedarpolicy.ParsedPolicySet{}.Source(), policy)
	require(err)
	set, err := rt.Templates().AddTemplate(ctx, parsed.Source(), templateID, template.TemplateFromCedar(
		`forbid(principal == ?principal, action == Action::"read", resource == ?resource) unless { context.mfa };`))
	require(err)
	set, err = rt.Templates().LinkTemplate(ctx, set, templateID, linkedID, template.SlotBindings{
		template.PrincipalSlot: principal, template.ResourceSlot: resource,
	})
	require(err)
	snapshot, err := rt.Policies().ParsePolicySet(ctx, set)
	require(err)
	snapshot, err = rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromJSON(snapshot.JSON()))
	require(err)
	static, ok := snapshot.Policy(permitID)
	if !ok || !static.IsStatic() || static.ID() != permitID || len(snapshot.Policies()) != 2 {
		t.Fatal("set snapshot lost the static policy or raw IDs")
	}
	if stage, ok := static.Annotation("stage"); !ok || stage != "json" {
		t.Fatal("set snapshot lost the JSON edit")
	}
	linked, ok := snapshot.Policy(linkedID)
	if !ok || linked.ID() != linkedID {
		t.Fatal("set snapshot lost the linked policy's raw ID")
	}
	if id, ok := linked.TemplateID(); !ok || id != templateID {
		t.Fatal("set snapshot flattened or changed the template link")
	}
	links, err := rt.Templates().TemplateLinks(ctx, snapshot.Source())
	require(err)
	if len(links) != 1 || links[0].PolicyID != linkedID || links[0].TemplateID != templateID || links[0].Bindings[template.PrincipalSlot] != principal || links[0].Bindings[template.ResourceSlot] != resource {
		t.Fatalf("snapshot changed link bindings: %+v", links)
	}
	validation, err := rt.Validation().Validate(ctx, schema, snapshot.Source())
	require(err)
	if !validation.Passed {
		t.Fatalf("combined policies are invalid: %+v", validation)
	}
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: snapshot.Source(), Limits: authorization.Limits{MaxInstances: 1}})
	require(err)
	defer a.Close()
	partial, err := a.Partial().PartialAuthorize(ctx, partialinput.PartialRequest{
		Principal: partialinput.KnownEntityUID(principal), Action: action, Resource: partialinput.KnownEntityUID(resource),
	})
	require(err)
	if partial.Decision != cedarpartial.Undecided || len(partial.Residuals) != 2 {
		t.Fatalf("unknown context/entities should leave both policies unresolved: %+v", partial)
	}
	residualIDs := make(map[string]bool)
	for _, residual := range partial.Residuals {
		if residual.State != cedarpartial.ResidualUnknown {
			t.Fatalf("unexpected decided residual: %+v", residual)
		}
		residualIDs[residual.PolicyID] = true
	}
	if !residualIDs[permitID] || !residualIDs[linkedID] {
		t.Fatalf("partial evaluation changed raw policy IDs: %v", residualIDs)
	}
	store := map[entityuid.EntityUID]cedarentity.Entity{
		principal: {UID: principal, Attrs: cedarvalue.Record{"active": cedarvalue.Bool(true)}},
		resource:  {UID: resource, Attrs: cedarvalue.Record{"public": cedarvalue.Bool(true)}},
	}
	full := cedarentity.NewEntities(store[principal], store[resource], cedarentity.Entity{
		UID: entityuid.NewEntityUID("User", "unused"), Attrs: cedarvalue.Record{"active": cedarvalue.Bool(false)},
	})
	for _, tc := range []struct {
		name   string
		mfa    bool
		want   cedarrequest.Decision
		reason string
	}{{"allow", true, cedarrequest.Allow, permitID}, {"deny", false, cedarrequest.Deny, linkedID}} {
		t.Run(tc.name, func(t *testing.T) {
			checkCombinedOutcome(t, combinedScenario{rt, a, partial, schema, snapshot.Source(), store, full, principal, action, resource}, tc.mfa, tc.want, tc.reason)
		})
	}
}
