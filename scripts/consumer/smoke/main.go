// This independent consumer runs native authorization and real solver analysis.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/ChrisMckerracher/cedar-cgo/analysis"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
	"github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
)

func main() {
	ctx := context.Background()
	runtime, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close(ctx)
	s := schema.SchemaFromCedar(`entity User; entity Doc; action read appliesTo {principal: User, resource: Doc, context: {n: Long}};`)
	authorizer, err := runtime.NewAuthorizer(ctx, authorization.Config{
		Schema: &s, Policies: policy.PoliciesFromCedar(`permit(principal, action, resource);`),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, request.Request{
		Principal: uid.NewEntityUID("User", "alice"),
		Action:    uid.NewEntityUID("Action", "read"),
		Resource:  uid.NewEntityUID("Doc", "example"), Context: request.ContextFromJSON([]byte(`{"n":0}`)),
	})
	if err != nil || response.Decision != request.Allow {
		log.Fatalf("authorization result: %v, error: %v", response.Decision, err)
	}
	analyzer, err := analysis.New(ctx, solver.CVC5(os.Getenv("CVC5")))
	if err != nil {
		log.Fatal(err)
	}
	defer analyzer.Close(ctx)
	a := policy.PoliciesFromCedar(`permit(principal, action, resource) when {context.n < 0};`)
	b := policy.PoliciesFromCedar(`permit(principal, action, resource) when {context.n <= -1};`)
	report, err := analyzer.Equivalent(ctx, s, a, b)
	if err != nil || len(report.Results) != 1 || !report.Holds() {
		log.Fatalf("solver equivalence result: %+v, error: %v", report, err)
	}
	b = policy.PoliciesFromCedar(`permit(principal, action, resource) when {context.n <= 0};`)
	report, err = analyzer.Equivalent(ctx, s, a, b)
	if err != nil || len(report.Results) != 1 || report.Holds() || report.Results[0].Counterexample == nil {
		log.Fatalf("solver counterexample result: %+v, error: %v", report, err)
	}
	fmt.Println("The source bundle runs native authorization and cvc5 analysis without Rust.")
}
