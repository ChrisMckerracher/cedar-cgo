package analysis_test

import (
	"context"
	"fmt"
	"log"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

// This example needs a cvc5 executable, so it has no Output comment and
// go test only compiles it.
func ExampleAnalyzer_NewlyPermitted() {
	ctx := context.Background()
	a, err := analysis.New(ctx, analysis.CVC5("/usr/local/bin/cvc5"))
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close(ctx)

	schema := cedar.SchemaFromCedar(`
entity User;
entity Doc;
action read, write appliesTo { principal: User, resource: Doc };
`)
	before := cedar.PoliciesFromCedar(`permit(principal, action == Action::"read", resource);`)
	after := cedar.PoliciesFromCedar(`permit(principal, action, resource);`)

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
