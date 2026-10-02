package cedar_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func ExampleRuntime_ParsePolicy() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	policy, err := rt.ParsePolicy(ctx, "read-photos", `@owner("photos") permit(principal, action == Action::"view", resource is Photo);`)
	if err != nil {
		log.Fatal(err)
	}
	owner, _ := policy.Annotation("owner")
	fmt.Println(policy.ID(), policy.Effect(), owner, policy.ResourceConstraint().EntityType)
	set, err := rt.AddPolicy(ctx, cedar.PoliciesFromCedar(""), policy)
	if err != nil {
		log.Fatal(err)
	}
	restored, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromJSON(set.JSON()))
	if err != nil {
		log.Fatal(err)
	}
	p, ok := restored.Policy("read-photos")
	fmt.Println(ok, p.ID())
	// Output:
	// read-photos permit photos Photo
	// true read-photos
}

func ExampleRuntime_PolicyFromSyntax() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	policy, err := rt.PolicyFromSyntax(ctx, cedar.PolicySyntax{
		ID: "require-mfa", Effect: cedar.Forbid,
		Principal:  cedar.ScopeConstraint{Kind: cedar.ConstraintAny},
		Action:     cedar.ActionConstraint{Kind: cedar.ConstraintAny},
		Resource:   cedar.ScopeConstraint{Kind: cedar.ConstraintAny},
		Conditions: []cedar.PolicyCondition{{Kind: "unless", Body: json.RawMessage(`{".":{"left":{"Var":"context"},"attr":"mfa"}}`)}},
	})
	if err != nil {
		log.Fatal(err)
	}
	set, err := rt.AddPolicy(ctx, cedar.PoliciesFromCedar("permit(principal,action,resource);"), policy)
	if err != nil {
		log.Fatal(err)
	}
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: set.Source()})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	result, err := a.Authorize(ctx, cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "one"), Context: cedar.NewContext(cedar.Record{"mfa": cedar.Bool(false)})})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Decision, result.Reasons)
	// Output: deny [require-mfa]
}
