package integration_test

import (
	context "context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	fixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fixture"
	fuzz "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fuzz"
	joy "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	os "os"
	filepath "path/filepath"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzPolicies(f *testing.F) {
	d := joy.LoadJoy(f)
	rt := testruntime.New(f)
	f.Add(d.Old.Text())
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
			f.Add(string(fixture.MustReadFile(f, name)))
		}
	}
	f.Fuzz(func(t *testing.T, TextValue string) {
		if fuzz.Nesting(TextValue) > fuzz.MaxFuzzNesting {
			t.Skip()
		}
		policies := cedarpolicy.PoliciesFromCedar(TextValue)
		_, err := rt.Validation().Validate(context.Background(), d.Schema, policies)
		fault.CheckNoFault(t, err)
		if !utf8.ValidString(TextValue) {
			fault.RequireUTF8InputError(t, err)
		}
		if err != nil {
			return
		}
		a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Schema: &d.Schema, Policies: policies, Entities: d.Entities, Limits: fuzz.FuzzLimits})
		fault.CheckNoFault(t, err)
		if err != nil {
			return
		}
		defer a.Close()
		resp, err := a.Authorize(context.Background(), joy.JoyRequest())
		fault.CheckNoFault(t, err)
		if err != nil && resp.Decision != cedarrequest.Deny {
			t.Fatalf("error %v came with %v", err, resp.Decision)
		}
	})
}
