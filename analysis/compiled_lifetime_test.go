package analysis_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	uids "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func TestCompiledEnvironmentSelectionAndLifetime(t *testing.T) {
	a, solver := compiledAnalyzer(t)
	ctx := context.Background()
	schema := schemas.SchemaFromCedar(`entity User; entity Document; action view appliesTo {principal: User, resource: Document, context: {n: Long}}; action edit appliesTo {principal: User, resource: Document, context: {n: Long}};`)
	selection := []analysis.RequestEnvironment{{PrincipalType: "User", Action: uids.NewEntityUID("Action", "view"), ResourceType: "Document"}}
	life, cancel := context.WithCancel(ctx)
	s, err := a.OpenCompiled(life, schema, selection)
	if err != nil {
		t.Fatal(err)
	}
	selection[0].PrincipalType = "changed"
	if len(s.Environments()) != 1 || s.Environments()[0].PrincipalType != "User" {
		t.Fatal("selection was not copied")
	}
	copy := s.Environments()
	copy[0].PrincipalType = "changed"
	if s.Environments()[0].PrincipalType != "User" {
		t.Fatal("environment readback changed the session")
	}
	handle, err := s.Compile(ctx, queryPolicy("permit", "context.n < 0"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := s.Equivalent(ctx, handle, handle)
	if err != nil || len(report.Results) != 1 || report.Results[0].Action.ID != "view" {
		t.Fatalf("selection report %+v %v", report, err)
	}
	valid := s.Environments()[0]
	if _, err := a.OpenCompiled(ctx, schema, []analysis.RequestEnvironment{valid, valid}); err == nil {
		t.Fatal("duplicate selection accepted")
	}
	invalid := valid
	invalid.Action = uids.NewEntityUID("Action", "missing")
	if _, err := a.OpenCompiled(ctx, schema, []analysis.RequestEnvironment{invalid}); err == nil {
		t.Fatal("unknown selection accepted")
	}
	empty, err := a.OpenCompiled(ctx, schema, []analysis.RequestEnvironment{})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := empty.Compile(ctx, queryPolicy("permit", ""))
	if err != nil {
		t.Fatal(err)
	}
	report, err = empty.Equivalent(ctx, zero, zero)
	if err != nil || len(report.Results) != 0 || !report.Holds() {
		t.Fatalf("empty selection %+v %v", report, err)
	}
	if _, err := empty.Compile(ctx, policy.PoliciesFromCedar(`permit(principal == ?principal,action,resource);`)); err == nil {
		t.Fatal("empty selection accepted template")
	}
	cancel()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Equivalent(ctx, handle, handle); !errors.Is(err, analysis.ErrCompiledClosed) {
		t.Fatalf("lifetime cancellation retained session %v", err)
	}
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if solver.starts.Load() != solver.closes.Load() {
		t.Fatal("failed constructors retained solvers")
	}
}
