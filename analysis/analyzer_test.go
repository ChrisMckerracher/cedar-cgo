package analysis_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	reports "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	requests "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newAnalyzer(t *testing.T) *analysis.Analyzer {
	t.Helper()
	path := os.Getenv("CVC5")
	if path == "" {
		t.Skip("CVC5 is not set to a cvc5 executable; see CONTRIBUTING.md")
	}
	a, err := analysis.New(context.Background(), solver.CVC5(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	return a
}

func TestNewlyPermittedJoy(t *testing.T) {
	a := newAnalyzer(t)
	ctx := context.Background()
	schema := schemas.SchemaFromCedar(readFile(t, "../testdata/joy/joy.cedarschema"))
	before := policy.PoliciesFromCedar(readFile(t, "../testdata/joy/old.cedar"))
	added := policy.PoliciesFromCedar(readFile(t, "../testdata/joy/new.cedar"))
	tight := policy.PoliciesFromCedar(readFile(t, "../testdata/joy/tight.cedar"))

	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	start := time.Now()
	report, err := a.NewlyPermitted(ctx, schema, before, added)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one added binding: %v", time.Since(start))
	widened := 0
	for _, r := range report.Results {
		if r.Holds {
			continue
		}
		widened++
		c := r.Counterexample
		if c.First != requests.Deny || c.Second != requests.Allow {
			t.Fatalf("%s: counterexample decisions before=%v after=%v", r.Action, c.First, c.Second)
		}
		checkWithAuthorizer(t, rt, schema, before, added, c)
	}
	if len(report.Results) != 10 || widened != 8 {
		t.Fatalf("one added binding widened %d of %d request environments, want 8 of 10", widened, len(report.Results))
	}

	start = time.Now()
	report, err = a.NewlyPermitted(ctx, schema, before, tight)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one raised device level: %v", time.Since(start))
	if !report.Holds() {
		t.Fatalf("a raised device level permits something new: %+v", report)
	}

	report, err = a.Equivalent(ctx, schema, before, before)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Holds() {
		t.Fatal("a policy set is not equivalent to itself")
	}
	report, err = a.Equivalent(ctx, schema, before, tight)
	if err != nil {
		t.Fatal(err)
	}
	if report.Holds() {
		t.Fatal("a raised device level is equivalent to the original")
	}
}

// Replay through Go to verify that counterexample decoding preserves the native result.
func checkWithAuthorizer(t *testing.T, rt *cedar.Runtime, schema schemas.Schema, before, after policy.PolicySet, c *reports.Counterexample) {
	t.Helper()
	ctx := context.Background()
	for _, tc := range []struct {
		policies policy.PolicySet
		want     requests.Decision
	}{{before, requests.Deny}, {after, requests.Allow}} {
		az, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: tc.policies})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := az.Authorize(ctx, c.Request)
		az.Close()
		if err != nil {
			t.Fatalf("replay %s: %v", c.Text, err)
		}
		if resp.Decision != tc.want {
			t.Fatalf("replay %s: got %v, want %v", c.Text, resp.Decision, tc.want)
		}
	}
}

func TestAnalysisRejectsInvalidPolicies(t *testing.T) {
	a := newAnalyzer(t)
	schema := schemas.SchemaFromCedar(readFile(t, "../testdata/joy/joy.cedarschema"))
	bad := policy.PoliciesFromCedar(`permit(principal, action, resource) when { context.deviceLevel == "high" };`)
	_, err := a.NewlyPermitted(context.Background(), schema, bad, bad)
	if err == nil || !strings.Contains(err.Error(), "compile") {
		t.Fatalf("got %v, want a compile error", err)
	}
}

func TestAnalysisSolverMissing(t *testing.T) {
	a, err := analysis.New(context.Background(), solver.CVC5("/nonexistent/cvc5"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	schema := schemas.SchemaFromCedar(readFile(t, "../testdata/joy/joy.cedarschema"))
	p := policy.PoliciesFromCedar(readFile(t, "../testdata/joy/old.cedar"))
	if _, err := a.Equivalent(context.Background(), schema, p, p); err == nil {
		t.Fatal("analysis without a solver succeeded")
	}
}
