package policy_test

import (
	context "context"
	json "encoding/json"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	log "log"
)

func Example_parsePolicy() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	policy, err := rt.Policies().ParsePolicy(ctx, "read-photos", `@owner("photos") permit(principal, action == Action::"view", resource is Photo);`)
	if err != nil {
		log.Fatal(err)
	}
	owner, _ := policy.Annotation("owner")
	fmt.Println(policy.ID(), policy.Effect(), owner, policy.ResourceConstraint().EntityType)
	set, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar(""), policy)
	if err != nil {
		log.Fatal(err)
	}
	restored, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromJSON(set.JSON()))
	if err != nil {
		log.Fatal(err)
	}
	p, ok := restored.Policy("read-photos")
	fmt.Println(ok, p.ID())
	// Output:
	// read-photos permit photos Photo
	// true read-photos
}

func Example_policyFromSyntax() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	policy, err := rt.Policies().PolicyFromSyntax(ctx, cedarpolicy.PolicySyntax{
		ID: "require-mfa", Effect: cedarpolicy.Forbid,
		Principal:  cedarpolicy.ScopeConstraint{Kind: cedarpolicy.ConstraintAny},
		Action:     cedarpolicy.ActionConstraint{Kind: cedarpolicy.ConstraintAny},
		Resource:   cedarpolicy.ScopeConstraint{Kind: cedarpolicy.ConstraintAny},
		Conditions: []cedarpolicy.PolicyCondition{{Kind: "unless", Body: json.RawMessage(`{".":{"left":{"Var":"context"},"attr":"mfa"}}`)}},
	})
	if err != nil {
		log.Fatal(err)
	}
	set, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar("permit(principal,action,resource);"), policy)
	if err != nil {
		log.Fatal(err)
	}
	a, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: set.Source()})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	result, err := a.Authorize(ctx, cedarrequest.Request{Principal: entityuid.NewEntityUID("User", "alice"), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "one"), Context: cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(false)})})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Decision, result.Reasons)
	// Output: deny [require-mfa]
}
