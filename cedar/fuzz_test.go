package cedar_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

// Generous budgets distinguish small-input crashes from expected resource-limit faults.
var fuzzLimits = cedar.Limits{MaxInstances: 1, CallTimeout: 10 * time.Second}

func checkNoFault(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, cedar.ErrFault) {
		t.Fatalf("module fault: %v", err)
	}
}

// Skip deep nesting because stack exhaustion has its own fail-closed test.
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
		for _, text := range []string{pType, pID, action, rType, rID, ctxJSON, entJSON} {
			if !utf8.ValidString(text) {
				requireUTF8InputError(t, err)
			}
		}
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
	// Corpus-derived literals keep extension-method and escape coverage without a corpus checkout.
	f.Add(`@r33234zzzzfzzz("")
forbid(
  principal == a::"",
  action,
  resource == a::"\u{1f}"
) when {
  true && (action in action) && ({"A23\0\u{4}\0\0\0\0\0\0": if false then datetime("0255-12-08T15:15:15.535+0015") else datetime("2194-01-01"), "^{{AAA{Debian {{\u{f}\u{f}\u{f}{\u{1f}": [] == true, "{{\0\0\0\0\0\0": if true then ip("ffff:ffff:ffff:ffff:3d3c:3d3d:3d3d:3d23/126") else ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/126")} has "\0\0")
};`)
	f.Add(`forbid(
  principal in a::"",
  action in [Action::""],
  resource in a::""
) when {
  true && (if false then {"": decimal("-122497909864477.4912")} else {"": decimal("-143Â2382260210.8929")})[""].lessThan((if false then {"": decimal("-441275054312267.7054")} else {"": decimal("-441275054312267.7054")})[""]) && (action in principal)
};`)
	f.Add(`permit(
  principal,
  action,
  resource
) when {
  true && ((if false then if false then "" else "" else if false then "" else "|||||") like "") && false
};`)
	f.Add(`forbid(
  principal,
  action in [Action::"action"],
  resource
) when {
  true && (datetime("{{]{{\0\0\0\0\0\0\0\01\u{3}\0\u{f}\0\u{2}").durationSince(datetime("5193-02-18").offset(duration("1d")).offset(duration("1ms"))) < datetime("\0\0\0\0\0\0").toTime()) && false && false
};`)
	f.Add(`forbid(
  principal in a::"R",
  action in [Action::"action",Action::"action"],
  resource in a::"R"
) when {
  true && ([[[ip("::"), ip("::2:d2d2:d2d2:0:0"), ip("::")], [ip("0:b48:4848:45e0:4848:82:ffff:3c50"), ip("0.0.0.0"), ip("0.0.0.0")], []], [], []] == []) && false
};`)
	f.Add(`@A("")
forbid(
  principal in a::"0",
  action in [Action::"action"],
  resource in a::"0"
) when {
  true && (if false then {"": decimal("0.1")} else {"": decimal("0.1")})[""].lessThan((if false then {"": decimal("0.1")} else {"": decimal("0.1")})[""]) && (if false then {"": decimal("0.1")} else {"": decimal("0.1")})[""].lessThan((if false then {"": decimal("0.1")} else {"": decimal("0.1")})[""])
};`)
	f.Add(`forbid(
  principal in r::"",
  action in [Action::"action",Action::"action"],
  resource in r::""
) when {
  true && [].contains(if [].contains([ip("f3f3:f3f3:f3f3:f3f3:f3f3:f34a:ffff:ffff/114"), ip("f3f3:f3f3:f3f3:f3f3:f3f3:f3f3:f3f3:f3f3/114"), ip("f3f3:f3f3:f3f3:f3f3:12f3:f3f3:f3f3:f3f3/114")]) then [] else []) && false
};`)
	f.Add(`permit(
  principal,
  action,
  resource
) when {
  true
};`)
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
		if !utf8.ValidString(text) {
			requireUTF8InputError(t, err)
		}
		if err != nil {
			return
		}
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
			if !utf8.ValidString(text) {
				requireUTF8InputError(t, err)
			}
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
