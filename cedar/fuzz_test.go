package cedar_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

// The fuzz targets check the boundary between Go and the module. For any
// input, a call returns either a response or an error, an error always
// comes with Deny, and the module never faults. A fault would mean that
// Cedar panicked or ran out of a resource on a small input.

// fuzzLimits gives fuzz inputs room, so that a fault means a crash and not
// a limit.
var fuzzLimits = cedar.Limits{MaxInstances: 1, CallTimeout: 10 * time.Second}

func checkNoFault(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, cedar.ErrFault) {
		t.Fatalf("module fault: %v", err)
	}
}

// nesting returns the deepest bracket nesting in s. Inputs nested deeper
// than maxFuzzNesting are skipped: the module traps on about 800 levels, as
// native Cedar does, and that limit has its own test.
func nesting(s string) int {
	depth, deepest := 0, 0
	for _, r := range s {
		switch r {
		case '(', '[', '{':
			depth++
			deepest = max(deepest, depth)
		case ')', ']', '}':
			depth--
		}
	}
	return deepest
}

const maxFuzzNesting = 200

func FuzzAuthorize(f *testing.F) {
	d := loadJoy(f)
	a, err := testRuntime(f).NewAuthorizer(context.Background(), cedar.Config{
		Schema: &d.schema, Policies: d.old, Entities: d.entities, Limits: fuzzLimits,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(a.Close)
	ctxJSON, _ := joyContext().MarshalJSON()
	f.Add("Joy::Device", "phone1", "session.write", "Joy::Session", "s1", string(ctxJSON), "")
	f.Add("Joy::Device", "phone1", "terminal.open", "Joy::Project", "proj1", `{"deviceLevel":2}`, `[{"uid":{"type":"Joy::Device","id":"x"},"attrs":{},"parents":[]}]`)
	f.Add("Joy::Device", "", "file.read", "Joy::Session", "\x00", `{"now":{"__extn":{"fn":"datetime","arg":"1969-12-31"}}}`, `[]`)
	f.Fuzz(func(t *testing.T, pType, pID, action, rType, rID, ctxJSON, entJSON string) {
		if nesting(ctxJSON) > maxFuzzNesting || nesting(entJSON) > maxFuzzNesting {
			t.Skip()
		}
		req := cedar.Request{
			Principal: cedar.NewEntityUID(pType, pID),
			Action:    cedar.NewEntityUID("Joy::Action", action),
			Resource:  cedar.NewEntityUID(rType, rID),
			Context:   cedar.ContextFromJSON([]byte(ctxJSON)),
		}
		if entJSON != "" {
			req.Entities = cedar.EntitiesFromJSON([]byte(entJSON))
		}
		resp, err := a.Authorize(context.Background(), req)
		checkNoFault(t, err)
		if err != nil && resp.Decision != cedar.Deny {
			t.Fatalf("error %v came with %v", err, resp.Decision)
		}
	})
}

func FuzzPolicies(f *testing.F) {
	d := loadJoy(f)
	rt := testRuntime(f)
	f.Add(d.old.Text())
	f.Add(`permit(principal is Joy::Device in Joy::Account::"a", action, resource) when { context.sourceIp.isInRange(ip("10.0.0.0/8")) && "x" like "*" };`)
	f.Add(`forbid(principal, action, resource) unless { context.now.toTime() >= duration("23h") || decimal("1.5").lessThan(decimal("2.0")) };`)
	f.Add(`@id("a") permit(principal == ?principal, action, resource);`)
	// With CEDAR_CORPUS_DIR set, the upstream corpus policies seed the run.
	if dir := os.Getenv("CEDAR_CORPUS_DIR"); dir != "" {
		files, _ := filepath.Glob(filepath.Join(dir, "corpus-tests", "*.cedar"))
		for _, name := range files[:min(len(files), 200)] {
			f.Add(string(readFile(f, name)))
		}
	}
	f.Fuzz(func(t *testing.T, text string) {
		if nesting(text) > maxFuzzNesting {
			t.Skip()
		}
		policies := cedar.PoliciesFromCedar(text)
		_, err := rt.Validate(context.Background(), d.schema, policies)
		checkNoFault(t, err)
		a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Schema: &d.schema, Policies: policies, Entities: d.entities, Limits: fuzzLimits})
		checkNoFault(t, err)
		if err != nil {
			return
		}
		defer a.Close()
		resp, err := a.Authorize(context.Background(), joyRequest())
		checkNoFault(t, err)
		if err != nil && resp.Decision != cedar.Deny {
			t.Fatalf("error %v came with %v", err, resp.Decision)
		}
	})
}

func FuzzEntities(f *testing.F) {
	d := loadJoy(f)
	rt := testRuntime(f)
	f.Add(string(readFile(f, "../testdata/joy/entities.json")))
	f.Add(`[{"uid":{"__entity":{"type":"Joy::Device","id":"d"}},"attrs":{},"parents":[{"type":"Joy::Account","id":"a"}],"tags":{}}]`)
	f.Add(`[{"uid":{"type":"Joy::Action","id":"session.read"},"attrs":{},"parents":[]}]`)
	f.Fuzz(func(t *testing.T, text string) {
		if nesting(text) > maxFuzzNesting {
			t.Skip()
		}
		for _, schema := range []*cedar.Schema{&d.schema, nil} {
			a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Schema: schema, Policies: d.old, Entities: cedar.EntitiesFromJSON([]byte(text)), Limits: fuzzLimits})
			checkNoFault(t, err)
			if err != nil {
				continue
			}
			resp, err := a.Authorize(context.Background(), joyRequest())
			a.Close()
			checkNoFault(t, err)
			if err != nil && resp.Decision != cedar.Deny {
				t.Fatalf("error %v came with %v", err, resp.Decision)
			}
		}
	})
}
