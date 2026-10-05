package utility_test

import (
	context "context"
	json "encoding/json"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	testing "testing"
	utf8 "unicode/utf8"
)

func FuzzConfusableStrings(f *testing.F) {
	rt := testsupport.TestRuntime(f)
	f.Add(`permit(principal, action, resource) when { "plain" == "plain" };`)
	f.Add(`permit(principal, action, resource) when { "aа" == "aа" };`)
	f.Add(`permit(principal == ?principal, action, resource);`)
	f.Add("\xff")
	f.Add(`invalid`)
	f.Fuzz(func(t *testing.T, TextValue string) {
		if testsupport.Nesting(TextValue) > testsupport.MaxFuzzNesting || len(TextValue) > 1<<20 {
			t.Skip()
		}
		policies := cedarpolicy.PoliciesFromCedar(TextValue)
		warnings, err := rt.Utilities().ConfusableStrings(context.Background(), policies)
		testsupport.CheckNoFault(t, err)
		if !utf8.ValidString(TextValue) {
			testsupport.RequireUtilKind(t, err, diagnostic.KindInput)
			return
		}
		if err != nil {
			testsupport.RequireUtilKind(t, err, diagnostic.KindPolicies)
			return
		}
		again, err := rt.Utilities().ConfusableStrings(context.Background(), policies)
		if err != nil || !reflect.DeepEqual(again, warnings) {
			t.Fatalf("unstable warnings: %+v vs %+v %v", warnings, again, err)
		}
		if testsupport.AsciiPlain(TextValue) && len(warnings) != 0 {
			t.Fatalf("plain ASCII policy has warnings: %+v", warnings)
		}
	})
}

func FuzzContextMerge(f *testing.F) {
	rt := testsupport.TestRuntime(f)
	f.Add([]byte(`{"a":1}`), []byte(`{"b":"x"}`))
	f.Add([]byte(`{"a":1}`), []byte(`{"a":1}`))
	f.Add([]byte(`{`), []byte(`[]`))
	f.Add([]byte(`{"a":"\xff"}`), []byte(`{}`))
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, left, right []byte) {
		if testsupport.Nesting(string(left)) > testsupport.MaxFuzzNesting || testsupport.Nesting(string(right)) > testsupport.MaxFuzzNesting ||
			len(left) > 1<<20 || len(right) > 1<<20 {
			t.Skip()
		}
		merged, err := cedarrequest.ContextFromJSON(left).Merge(context.Background(), rt.Utilities(), cedarrequest.ContextFromJSON(right))
		testsupport.CheckNoFault(t, err)
		if !utf8.ValidString(string(left)) || !utf8.ValidString(string(right)) {
			testsupport.RequireUtilKind(t, err, diagnostic.KindInput)
			return
		}
		leftObject, leftScalars := testsupport.FuzzObjectContext(left)
		rightObject, rightScalars := testsupport.FuzzObjectContext(right)
		if !leftScalars || !rightScalars {
			return
		}
		for key := range rightObject {
			if _, ok := leftObject[key]; ok {
				testsupport.RequireUtilKind(t, err, diagnostic.KindContext)
				return
			}
		}
		if err != nil {
			t.Fatalf("disjoint scalar merge failed: %v", err)
		}
		raw, merr := json.Marshal(merged)
		if merr != nil {
			t.Fatal(merr)
		}
		var object map[string]json.RawMessage
		if jerr := json.Unmarshal(raw, &object); jerr != nil {
			t.Fatalf("merged context is not a JSON object: %v", jerr)
		}
		if len(object) != len(leftObject)+len(rightObject) {
			t.Fatalf("merged keys %d, want %d+%d: %s", len(object), len(leftObject), len(rightObject), raw)
		}
		for _, source := range []map[string]json.RawMessage{leftObject, rightObject} {
			for key := range source {
				if _, ok := object[key]; !ok {
					t.Fatalf("merged context lost key %q: %s", key, raw)
				}
			}
		}
	})
}
