package analysis_test

import (
	"context"
	"fmt"
	"log"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

// Omit Output because running the example requires an external cvc5 executable.
func ExampleAnalyzer_NewlyPermitted() {
	ctx := context.Background()
	a, err := analysis.New(ctx, solver.CVC5("/usr/local/bin/cvc5"))
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close(ctx)

	schema := schemas.SchemaFromCedar(`
entity User;
entity Doc;
action read, write appliesTo { principal: User, resource: Doc };
`)
	before := policy.PoliciesFromCedar(`permit(principal, action == Action::"read", resource);`)
	after := policy.PoliciesFromCedar(`permit(principal, action, resource);`)

	report, err := a.NewlyPermitted(ctx, schema, before, after)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range report.Results {
		if !r.Holds {
			fmt.Printf("%s now allowed, for example: %s\n", r.Action, r.Counterexample.Text)
		}
	}
}
