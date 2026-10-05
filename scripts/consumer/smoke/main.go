// This independent consumer exercises both embedded modules without Rust or cvc5.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type unusedSolver struct{}
type unusedSession struct{}

func (unusedSolver) Start(context.Context) (analysis.Session, error) { return unusedSession{}, nil }
func (unusedSession) Read([]byte) (int, error)                       { return 0, io.EOF }
func (unusedSession) Write([]byte) (int, error)                      { return 0, errors.New("unexpected solver input") }
func (unusedSession) Close() error                                   { return nil }

func main() {
	ctx := context.Background()
	runtime, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close(ctx)
	authorizer, err := runtime.NewAuthorizer(ctx, cedar.Config{
		Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource);`),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer authorizer.Close()
	response, err := authorizer.Authorize(ctx, cedar.Request{
		Principal: cedar.NewEntityUID("User", "alice"),
		Action:    cedar.NewEntityUID("Action", "read"),
		Resource:  cedar.NewEntityUID("Doc", "example"),
	})
	if err != nil || response.Decision != cedar.Allow {
		log.Fatalf("authorization result: %v, error: %v", response.Decision, err)
	}
	analyzer, err := analysis.New(ctx, unusedSolver{})
	if err != nil {
		log.Fatal(err)
	}
	defer analyzer.Close(ctx)
	// Invalid syntax exercises the analysis guest before it needs a solver reply.
	_, err = analyzer.Equivalent(ctx, cedar.SchemaFromCedar("invalid schema"), cedar.PolicySet{}, cedar.PolicySet{})
	var analysisError *analysis.Error
	if !errors.As(err, &analysisError) || analysisError.Kind != "schema" {
		log.Fatalf("analysis schema result: %v", err)
	}
	fmt.Println("The source bundle runs both embedded modules without Rust.")
}
