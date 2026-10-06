package policy_test

import (
	context "context"
	json "encoding/json/v2"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
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
	var document struct {
		Resource struct {
			EntityType string `json:"entity_type"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(policy.JSON(), &document); err != nil {
		log.Fatal(err)
	}
	fmt.Println(policy.ID(), policy.Effect(), owner, document.Resource.EntityType)
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

func Example_policyFromJSON() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	policy, err := rt.Policies().PolicyFromJSON(ctx, "require-mfa", []byte(`{
		"effect":"forbid", "principal":{"op":"All"}, "action":{"op":"All"}, "resource":{"op":"All"},
		"conditions":[{"kind":"unless","body":{".":{"left":{"Var":"context"},"attr":"mfa"}}}]
	}`))
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
