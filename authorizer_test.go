package cedar_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm"
	"github.com/tetratelabs/wazero"
)

var (
	sharedRuntime     *cedar.Runtime
	sharedRuntimeOnce sync.Once
	sharedRuntimeErr  error
)

// testRuntime returns one Runtime for the whole test binary, because
// compiling the module takes seconds. A file cache shares the compiled
// code with the worker processes of a fuzz run.
func testRuntime(t testing.TB) *cedar.Runtime {
	t.Helper()
	sharedRuntimeOnce.Do(func() {
		var cache wazero.CompilationCache
		cache, sharedRuntimeErr = wazero.NewCompilationCacheWithDir(filepath.Join(os.TempDir(), "cedar-go-wasm-test-cache"))
		if sharedRuntimeErr != nil {
			return
		}
		sharedRuntime, sharedRuntimeErr = cedar.NewRuntime(context.Background(), cedar.WithCompilationCache(cache))
	})
	if sharedRuntimeErr != nil {
		t.Fatal(sharedRuntimeErr)
	}
	return sharedRuntime
}

func readFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type joyData struct {
	schema   cedar.Schema
	old      cedar.PolicySet
	new      cedar.PolicySet
	tight    cedar.PolicySet
	entities cedar.Entities
}

func loadJoy(t testing.TB) joyData {
	return joyData{
		schema:   cedar.SchemaFromCedar(string(readFile(t, "testdata/joy/joy.cedarschema"))),
		old:      cedar.PoliciesFromCedar(string(readFile(t, "testdata/joy/old.cedar"))),
		new:      cedar.PoliciesFromCedar(string(readFile(t, "testdata/joy/new.cedar"))),
		tight:    cedar.PoliciesFromCedar(string(readFile(t, "testdata/joy/tight.cedar"))),
		entities: cedar.EntitiesFromJSON(readFile(t, "testdata/joy/entities.json")),
	}
}

func joyContext() cedar.Context {
	return cedar.NewContext(cedar.Record{
		"deviceLevel":     cedar.Long(1),
		"platform":        cedar.Record{"os": cedar.String("ios"), "model": cedar.String("iPhone17,1"), "securityLevel": cedar.Long(3)},
		"sessionId":       cedar.String("s1"),
		"now":             cedar.Datetime("2026-10-01T12:00:00Z"),
		"machineAttested": cedar.Bool(true),
		"sourceIp":        cedar.IPAddr("10.1.2.3"),
	})
}

func joyRequest() cedar.Request {
	return cedar.Request{
		Principal: cedar.NewEntityUID("Joy::Device", "phone1"),
		Action:    cedar.NewEntityUID("Joy::Action", "session.write"),
		Resource:  cedar.NewEntityUID("Joy::Session", "s1"),
		Context:   joyContext(),
	}
}

func newJoyAuthorizer(t testing.TB, limits cedar.Limits) *cedar.Authorizer {
	t.Helper()
	d := loadJoy(t)
	a, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{
		Schema:   &d.schema,
		Policies: d.old,
		Entities: d.entities,
		Limits:   limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func TestAuthorizeJoy(t *testing.T) {
	a := newJoyAuthorizer(t, cedar.Limits{})
	resp, err := a.Authorize(context.Background(), joyRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != cedar.Allow || len(resp.Reasons) != 1 || resp.Reasons[0] != "policy1" {
		t.Fatalf("got %+v, want allow by policy1", resp)
	}

	req := joyRequest()
	req.Action = cedar.NewEntityUID("Joy::Action", "terminal.open")
	resp, err = a.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != cedar.Deny {
		t.Fatalf("terminal.open at device level 1: got %+v, want deny", resp)
	}
}

func TestAuthorizeRequestEntities(t *testing.T) {
	a := newJoyAuthorizer(t, cedar.Limits{})
	req := joyRequest()
	req.Principal = cedar.NewEntityUID("Joy::Device", "tablet9")
	resp, err := a.Authorize(context.Background(), req)
	if err != nil || resp.Decision != cedar.Deny {
		t.Fatalf("unknown device: got %+v, %v; want deny", resp, err)
	}
	req.Entities = cedar.NewEntities(cedar.Entity{
		UID:     req.Principal,
		Parents: []cedar.EntityUID{cedar.NewEntityUID("Joy::Account", "acct1")},
	})
	resp, err = a.Authorize(context.Background(), req)
	if err != nil || resp.Decision != cedar.Allow {
		t.Fatalf("device added for the request: got %+v, %v; want allow", resp, err)
	}
}

func TestAuthorizeErrorsDeny(t *testing.T) {
	a := newJoyAuthorizer(t, cedar.Limits{})
	cases := map[string]struct {
		mutate func(*cedar.Request)
		kind   cedar.ErrorKind
	}{
		"context type": {func(r *cedar.Request) {
			r.Context = cedar.NewContext(cedar.Record{"deviceLevel": cedar.String("high")})
		}, cedar.KindContext},
		"undeclared action": {func(r *cedar.Request) {
			r.Action = cedar.NewEntityUID("Joy::Action", "nope")
		}, cedar.KindContext},
		"principal type": {func(r *cedar.Request) {
			r.Principal = cedar.NewEntityUID("Joy::Session", "s1")
		}, cedar.KindRequest},
		"bad type name": {func(r *cedar.Request) {
			r.Principal = cedar.NewEntityUID("not a name", "x")
		}, cedar.KindPrincipal},
		"invalid context JSON": {func(r *cedar.Request) {
			r.Context = cedar.ContextFromJSON([]byte(`{"deviceLevel":`))
		}, cedar.KindInput},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := joyRequest()
			c.mutate(&req)
			resp, err := a.Authorize(context.Background(), req)
			if resp.Decision != cedar.Deny {
				t.Fatalf("got %v, want deny", resp.Decision)
			}
			var cerr *cedar.Error
			if !errors.As(err, &cerr) || cerr.Kind != c.kind {
				t.Fatalf("got error %v, want kind %s", err, c.kind)
			}
		})
	}
	if s := a.Stats(); s.Discarded != 0 {
		t.Fatalf("Cedar input errors discarded %d instances, want 0", s.Discarded)
	}
}

func TestNewAuthorizerRejectsBadPolicies(t *testing.T) {
	_, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{
		Policies: cedar.PoliciesFromCedar("permit(principal, action, resource) when { 1 + };"),
	})
	var cerr *cedar.Error
	if !errors.As(err, &cerr) || cerr.Kind != cedar.KindPolicies {
		t.Fatalf("got %v, want a policies error", err)
	}
}

func TestValidate(t *testing.T) {
	d := loadJoy(t)
	rt := testRuntime(t)
	res, err := rt.Validate(context.Background(), d.schema, d.old)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Fatalf("joy policies failed strict validation: %+v", res.Errors)
	}
	res, err = rt.Validate(context.Background(), d.schema,
		cedar.PoliciesFromCedar(`permit(principal, action, resource) when { context.deviceLevel == "high" };`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed || len(res.Errors) == 0 || res.Errors[0].PolicyID != "policy0" {
		t.Fatalf("type error passed strict validation: %+v", res)
	}
}
