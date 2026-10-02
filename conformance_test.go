package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm"
)

// corpusTest is one test in Cedar's integration-test corpus. The format is
// cedar-testing's JsonTest, which the Rust implementation runs in CI.
type corpusTest struct {
	Policies       string          `json:"policies"`
	PolicyFormat   string          `json:"policyFormat"`
	Entities       string          `json:"entities"`
	Schema         string          `json:"schema"`
	SchemaFormat   string          `json:"schemaFormat"`
	ShouldValidate bool            `json:"shouldValidate"`
	Requests       []corpusRequest `json:"requests"`
}

type corpusRequest struct {
	Description     string          `json:"description"`
	Principal       corpusUID       `json:"principal"`
	Action          corpusUID       `json:"action"`
	Resource        corpusUID       `json:"resource"`
	Context         json.RawMessage `json:"context"`
	ValidateRequest *bool           `json:"validateRequest"`
	Decision        string          `json:"decision"`
	Reason          []string        `json:"reason"`
	Errors          []string        `json:"errors"`
}

// corpusUID accepts both entity reference forms that the corpus may use:
// {"type": ..., "id": ...} and {"__entity": {"type": ..., "id": ...}}.
type corpusUID struct{ cedar.EntityUID }

func (u *corpusUID) UnmarshalJSON(b []byte) error {
	var v struct {
		Type   *string `json:"type"`
		ID     *string `json:"id"`
		Entity *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"__entity"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	switch {
	case v.Entity != nil && v.Type == nil && v.ID == nil:
		u.EntityUID = cedar.NewEntityUID(v.Entity.Type, v.Entity.ID)
	case v.Entity == nil && v.Type != nil && v.ID != nil:
		u.EntityUID = cedar.NewEntityUID(*v.Type, *v.ID)
	default:
		return fmt.Errorf("unrecognized entity reference %s", b)
	}
	return nil
}

type corpusTally struct {
	mu                 sync.Mutex
	tests, requests    int
	decisionMismatch   int
	reasonMismatch     int
	errorMismatch      int
	validationMismatch int
	setupFailure       int
	requestFailure     int
	examples           []string
}

func (c *corpusTally) note(counter *int, format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*counter++
	if len(c.examples) < 50 {
		c.examples = append(c.examples, fmt.Sprintf(format, args...))
	}
}

// TestCorpus runs Cedar's integration-test corpus through the Go API. Set
// CEDAR_CORPUS_DIR to the directory that holds corpus-tests/. The test
// requires zero mismatches in decisions, reasons, errors and strict
// validation.
func TestCorpus(t *testing.T) {
	dir := os.Getenv("CEDAR_CORPUS_DIR")
	if dir == "" {
		t.Skip("CEDAR_CORPUS_DIR is not set; see CONTRIBUTING.md")
	}
	files, err := filepath.Glob(filepath.Join(dir, "corpus-tests", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	files = slices.DeleteFunc(files, func(f string) bool { return strings.HasSuffix(f, ".entities.json") })
	if len(files) == 0 {
		t.Fatalf("no corpus tests in %s", dir)
	}
	rt := testRuntime(t)
	var tally corpusTally
	work := make(chan string)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for f := range work {
				runCorpusTest(rt, dir, f, &tally)
			}
		})
	}
	for _, f := range files {
		work <- f
	}
	close(work)
	wg.Wait()

	t.Logf("tests=%d requests=%d decisionMismatch=%d reasonMismatch=%d errorMismatch=%d validationMismatch=%d setupFailure=%d requestFailure=%d",
		tally.tests, tally.requests, tally.decisionMismatch, tally.reasonMismatch, tally.errorMismatch,
		tally.validationMismatch, tally.setupFailure, tally.requestFailure)
	for _, e := range tally.examples {
		t.Log(e)
	}
	if tally.decisionMismatch+tally.reasonMismatch+tally.errorMismatch+tally.validationMismatch+tally.setupFailure+tally.requestFailure != 0 {
		t.Fatal("the corpus disagrees with this package")
	}
	if tally.requests == 0 {
		t.Fatal("the corpus has no requests")
	}
}

func parsePolicies(format, text string) cedar.PolicySet {
	if format == "json" {
		return cedar.PoliciesFromJSON([]byte(text))
	}
	return cedar.PoliciesFromCedar(text)
}

func parseSchema(format, text string) cedar.Schema {
	if format == "json" {
		return cedar.SchemaFromJSON([]byte(text))
	}
	return cedar.SchemaFromCedar(text)
}

func runCorpusTest(rt *cedar.Runtime, dir, file string, tally *corpusTally) {
	ctx := context.Background()
	name := filepath.Base(file)
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			tally.note(&tally.setupFailure, "%s: %v", name, err)
		}
		return b
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		tally.note(&tally.setupFailure, "%s: %v", name, err)
		return
	}
	var tt corpusTest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tt); err != nil {
		tally.note(&tally.setupFailure, "%s: decode test: %v", name, err)
		return
	}
	tally.mu.Lock()
	tally.tests++
	tally.requests += len(tt.Requests)
	tally.mu.Unlock()

	schema := parseSchema(tt.SchemaFormat, string(read(tt.Schema)))
	policies := parsePolicies(tt.PolicyFormat, string(read(tt.Policies)))
	entities := cedar.EntitiesFromJSON(read(tt.Entities))

	res, err := rt.Validate(ctx, schema, policies)
	switch {
	case err != nil:
		tally.note(&tally.validationMismatch, "%s: validate: %v", name, err)
	case res.Passed != tt.ShouldValidate:
		tally.note(&tally.validationMismatch, "%s: strict validation passed=%v, corpus says %v: %+v", name, res.Passed, tt.ShouldValidate, res.Errors)
	}

	a, err := rt.NewAuthorizer(ctx, cedar.Config{
		Schema:   &schema,
		Policies: policies,
		Entities: entities,
		Limits:   cedar.Limits{MaxInstances: 1, CallTimeout: -1},
	})
	if err != nil {
		tally.note(&tally.setupFailure, "%s: load: %v", name, err)
		return
	}
	defer a.Close()

	for _, r := range tt.Requests {
		if r.ValidateRequest != nil && !*r.ValidateRequest {
			tally.note(&tally.requestFailure, "%s: %s: validateRequest=false is not supported", name, r.Description)
			continue
		}
		resp, err := a.Authorize(ctx, cedar.Request{
			Principal: r.Principal.EntityUID,
			Action:    r.Action.EntityUID,
			Resource:  r.Resource.EntityUID,
			Context:   cedar.ContextFromJSON(r.Context),
		})
		if err != nil {
			tally.note(&tally.requestFailure, "%s: %s: %v", name, r.Description, err)
			continue
		}
		if resp.Decision.String() != r.Decision {
			tally.note(&tally.decisionMismatch, "%s: %s: decision %s, corpus says %s", name, r.Description, resp.Decision, r.Decision)
		}
		if !sameSet(resp.Reasons, r.Reason) {
			tally.note(&tally.reasonMismatch, "%s: %s: reasons %v, corpus says %v", name, r.Description, resp.Reasons, r.Reason)
		}
		var errIDs []string
		for _, e := range resp.Errors {
			errIDs = append(errIDs, e.PolicyID)
		}
		if !sameSet(errIDs, r.Errors) {
			tally.note(&tally.errorMismatch, "%s: %s: errors %v, corpus says %v", name, r.Description, errIDs, r.Errors)
		}
	}
}

// sameSet compares two lists of policy IDs as sets, as cedar-testing does.
func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
