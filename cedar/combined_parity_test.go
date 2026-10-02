package cedar_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestCombinedPolicyEvaluationPaths(t *testing.T) {
	ctx, rt := context.Background(), testRuntime(t)
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	const suffix = "\"\n\\雪"
	const permitID, templateID, linkedID = "permit" + suffix, "template" + suffix, "linked" + suffix
	principal, resource := cedar.NewEntityUID("User", "alice"+suffix), cedar.NewEntityUID("Document", "one"+suffix)
	action := cedar.NewEntityUID("Action", "read")
	schema := cedar.SchemaFromCedar(`entity User { active: Bool }; entity Document { public: Bool }; action read appliesTo { principal: User, resource: Document, context: { mfa: Bool } };`)

	formatted, err := rt.FormatPolicies(ctx, `@owner("integration") permit(principal is User,action==Action::"read",resource is Document)when{principal.active&&resource.public};`)
	require(err)
	policy, err := rt.ParsePolicy(ctx, permitID, formatted)
	require(err)
	syntax, err := policy.Syntax()
	require(err)
	syntax.Annotations["stage"] = "pst"
	policy, err = rt.PolicyFromSyntax(ctx, syntax)
	require(err)
	if policy.ID() != permitID || policy.Effect() != cedar.Permit {
		t.Fatalf("PST reconstruction changed identity/effect: %q %s", policy.ID(), policy.Effect())
	}
	parsed, err := rt.AddPolicy(ctx, cedar.ParsedPolicySet{}.Source(), policy)
	require(err)
	set, err := rt.AddTemplate(ctx, parsed.Source(), templateID, cedar.TemplateFromCedar(
		`forbid(principal == ?principal, action == Action::"read", resource == ?resource) unless { context.mfa };`))
	require(err)
	set, err = rt.LinkTemplate(ctx, set, templateID, linkedID, cedar.SlotBindings{
		cedar.PrincipalSlot: principal, cedar.ResourceSlot: resource,
	})
	require(err)
	snapshot, err := rt.ParsePolicySet(ctx, set)
	require(err)
	snapshot, err = rt.ParsePolicySet(ctx, cedar.PoliciesFromJSON(snapshot.JSON()))
	require(err)
	static, ok := snapshot.Policy(permitID)
	if !ok || !static.IsStatic() || static.ID() != permitID || len(snapshot.Policies()) != 2 {
		t.Fatal("set snapshot lost the static policy or raw IDs")
	}
	if stage, ok := static.Annotation("stage"); !ok || stage != "pst" {
		t.Fatal("set snapshot lost the PST edit")
	}
	linked, ok := snapshot.Policy(linkedID)
	if !ok || linked.ID() != linkedID {
		t.Fatal("set snapshot lost the linked policy's raw ID")
	}
	if id, ok := linked.TemplateID(); !ok || id != templateID {
		t.Fatal("set snapshot flattened or changed the template link")
	}
	links, err := rt.TemplateLinks(ctx, snapshot.Source())
	require(err)
	if len(links) != 1 || links[0].PolicyID != linkedID || links[0].TemplateID != templateID || links[0].Bindings[cedar.PrincipalSlot] != principal || links[0].Bindings[cedar.ResourceSlot] != resource {
		t.Fatalf("snapshot changed link bindings: %+v", links)
	}
	validation, err := rt.Validate(ctx, schema, snapshot.Source())
	require(err)
	if !validation.Passed {
		t.Fatalf("combined policies are invalid: %+v", validation)
	}
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: snapshot.Source(), Limits: cedar.Limits{MaxInstances: 1}})
	require(err)
	defer a.Close()
	partial, err := a.PartialAuthorize(ctx, cedar.PartialRequest{
		Principal: cedar.KnownEntityUID(principal), Action: action, Resource: cedar.KnownEntityUID(resource),
	})
	require(err)
	if partial.Decision != cedar.Undecided || len(partial.Residuals) != 2 {
		t.Fatalf("unknown context/entities should leave both policies unresolved: %+v", partial)
	}
	residualIDs := make(map[string]bool)
	for _, residual := range partial.Residuals {
		if residual.State != cedar.ResidualUnknown {
			t.Fatalf("unexpected decided residual: %+v", residual)
		}
		residualIDs[residual.PolicyID] = true
	}
	if !residualIDs[permitID] || !residualIDs[linkedID] {
		t.Fatalf("partial evaluation changed raw policy IDs: %v", residualIDs)
	}
	store := map[cedar.EntityUID]cedar.Entity{
		principal: {UID: principal, Attrs: cedar.Record{"active": cedar.Bool(true)}},
		resource:  {UID: resource, Attrs: cedar.Record{"public": cedar.Bool(true)}},
	}
	full := cedar.NewEntities(store[principal], store[resource], cedar.Entity{
		UID: cedar.NewEntityUID("User", "unused"), Attrs: cedar.Record{"active": cedar.Bool(false)},
	})
	for _, tc := range []struct {
		name   string
		mfa    bool
		want   cedar.Decision
		reason string
	}{{"allow", true, cedar.Allow, permitID}, {"deny", false, cedar.Deny, linkedID}} {
		t.Run(tc.name, func(t *testing.T) {
			checkResponse := func(path string, response cedar.Response, err error) {
				t.Helper()
				if err != nil || response.Decision != tc.want || len(response.Errors) != 0 || len(response.Reasons) != 1 || response.Reasons[0] != tc.reason {
					t.Fatalf("%s: %+v, %v; want %s with raw reason %q", path, response, err, tc.want, tc.reason)
				}
			}
			req := cedar.Request{Principal: principal, Action: action, Resource: resource,
				Context: cedar.NewContext(cedar.Record{"mfa": cedar.Bool(tc.mfa)}), Entities: full}
			response, err := a.Authorize(ctx, req)
			checkResponse("ordinary", response, err)
			response, err = partial.Reauthorize(ctx, req)
			checkResponse("reauthorize", response, err)

			// The callback must supply data even after ordinary calls used full request entities.
			req.Entities = cedar.Entities{}
			calls := 0
			decision, err := a.AuthorizeBatched(ctx, req, cedar.EntityLoaderFunc(func(_ context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
				calls++
				entities := make([]cedar.Entity, 0, len(uids))
				for _, uid := range uids {
					entity, ok := store[uid]
					if !ok {
						return cedar.EntityLoadResult{}, fmt.Errorf("unexpected requested entity: %v", uid)
					}
					entities = append(entities, entity)
				}
				data, err := json.Marshal(cedar.NewEntities(entities...))
				return cedar.EntityLoadResult{Entities: data}, err
			}), cedar.BatchedOptions{MaxIterations: 4})
			if err != nil || decision != tc.want || (tc.mfa && calls == 0) {
				t.Fatalf("batched: %s, %v, callbacks=%d; want %s", decision, err, calls, tc.want)
			}
			slice, err := rt.SliceEntities(ctx, cedar.SliceConfig{Schema: schema, Policies: snapshot.Source(), Entities: full}, req)
			if err != nil || slice.Decision != tc.want {
				t.Fatalf("slice: %+v, %v; want %s", slice, err, tc.want)
			}
			data, err := json.Marshal(slice.Entities)
			if err != nil {
				t.Fatal(err)
			}
			var retained []json.RawMessage
			if err := json.Unmarshal(data, &retained); err != nil || len(retained) >= 3 || (tc.mfa && (len(retained) != 2 || len(slice.Batches) == 0)) {
				t.Fatalf("expected a request-specific reduction: entities=%s, batches=%v, err=%v", data, slice.Batches, err)
			}
			// A fresh authorizer prevents full request data or callback caches from masking a bad slice.
			reduced, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: snapshot.Source(), Entities: slice.Entities})
			if err != nil {
				t.Fatal(err)
			}
			defer reduced.Close()
			response, err = reduced.Authorize(ctx, req)
			// Slicing preserves decisions; errors from policies irrelevant to that decision may differ.
			if err != nil || response.Decision != tc.want {
				t.Fatalf("reduced: %+v, %v; want %s", response, err, tc.want)
			}
		})
	}
}
