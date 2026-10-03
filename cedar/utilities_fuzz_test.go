package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

// fuzzUtilSchema declares exactly one fitting scope triple: User / Action::"view" / Photo.
const fuzzUtilSchema = `entity User; entity Photo; action "view" appliesTo { principal: User, resource: Photo, context: {} };`

func requireUtilKind(t *testing.T, err error, want cedar.ErrorKind) {
	t.Helper()
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != want {
		t.Fatalf("want %s error, got %v", want, err)
	}
}

// asciiPlain reports printable-ASCII, backslash-free text: backslashes are
// excluded because escape sequences can spell mixed-script values in ASCII source.
func asciiPlain(text string) bool {
	return !strings.Contains(text, `\`) &&
		strings.IndexFunc(text, func(r rune) bool { return r < 0x20 || r > 0x7e }) == -1
}

func FuzzConfusableStrings(f *testing.F) {
	rt := testRuntime(f)
	f.Add(`permit(principal, action, resource) when { "plain" == "plain" };`)
	f.Add(`permit(principal, action, resource) when { "aа" == "aа" };`)
	f.Add(`permit(principal == ?principal, action, resource);`)
	f.Add("\xff")
	f.Add(`invalid`)
	f.Fuzz(func(t *testing.T, text string) {
		if nesting(text) > maxFuzzNesting || len(text) > 1<<20 {
			t.Skip()
		}
		policies := cedar.PoliciesFromCedar(text)
		warnings, err := rt.ConfusableStrings(context.Background(), policies)
		checkNoFault(t, err)
		if !utf8.ValidString(text) {
			requireUtilKind(t, err, cedar.KindInput)
			return
		}
		if err != nil {
			requireUtilKind(t, err, cedar.KindPolicies)
			return
		}
		again, err := rt.ConfusableStrings(context.Background(), policies)
		if err != nil || !reflect.DeepEqual(again, warnings) {
			t.Fatalf("unstable warnings: %+v vs %+v %v", warnings, again, err)
		}
		if asciiPlain(text) && len(warnings) != 0 {
			t.Fatalf("plain ASCII policy has warnings: %+v", warnings)
		}
	})
}

// fuzzCanonicalLong accepts exactly the integer literals Cedar's JSON encoding
// round-trips; "-0", exponents, and out-of-range numbers are module errors.
func fuzzCanonicalLong(text string) bool {
	if text == "-0" {
		return false
	}
	body := strings.TrimPrefix(text, "-")
	if body == "0" {
		return true
	}
	if body == "" || body[0] < '1' || body[0] > '9' {
		return false
	}
	for i := 1; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(text, 10, 64)
	return err == nil
}

// fuzzObjectContext parses a JSON object and reports whether every value is a
// plain Cedar scalar: bool, canonical long, or string. Nested values opt out.
func fuzzObjectContext(data []byte) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return nil, false
	}
	for _, raw := range object {
		text := strings.TrimSpace(string(raw))
		switch {
		case text == "true" || text == "false" || strings.HasPrefix(text, `"`):
		case strings.HasPrefix(text, "-") || (text != "" && text[0] >= '0' && text[0] <= '9'):
			if !fuzzCanonicalLong(text) {
				return object, false
			}
		default:
			return object, false
		}
	}
	return object, true
}

func FuzzContextMerge(f *testing.F) {
	rt := testRuntime(f)
	f.Add([]byte(`{"a":1}`), []byte(`{"b":"x"}`))
	f.Add([]byte(`{"a":1}`), []byte(`{"a":1}`))
	f.Add([]byte(`{`), []byte(`[]`))
	f.Add([]byte(`{"a":"\xff"}`), []byte(`{}`))
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, left, right []byte) {
		if nesting(string(left)) > maxFuzzNesting || nesting(string(right)) > maxFuzzNesting ||
			len(left) > 1<<20 || len(right) > 1<<20 {
			t.Skip()
		}
		merged, err := cedar.ContextFromJSON(left).Merge(context.Background(), rt, cedar.ContextFromJSON(right))
		checkNoFault(t, err)
		if !utf8.ValidString(string(left)) || !utf8.ValidString(string(right)) {
			requireUtilKind(t, err, cedar.KindInput)
			return
		}
		leftObject, leftScalars := fuzzObjectContext(left)
		rightObject, rightScalars := fuzzObjectContext(right)
		if !leftScalars || !rightScalars {
			return
		}
		for key := range rightObject {
			if _, ok := leftObject[key]; ok {
				requireUtilKind(t, err, cedar.KindContext)
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

func FuzzScopeValidation(f *testing.F) {
	rt := testRuntime(f)
	schema := cedar.SchemaFromCedar(fuzzUtilSchema)
	f.Add("User", "view", "Photo")
	f.Add("Photo", "view", "Photo")
	f.Add("User", "edit", "Photo")
	f.Add("\xff", "view", "Photo")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, pType, actionID, rType string) {
		if len(pType)+len(actionID)+len(rType) > 1<<20 {
			t.Skip()
		}
		err := rt.ValidateScopeVariables(context.Background(), schema,
			cedar.NewEntityUID(pType, "x"), cedar.NewEntityUID("Action", actionID), cedar.NewEntityUID(rType, "p"))
		checkNoFault(t, err)
		if !utf8.ValidString(pType) || !utf8.ValidString(actionID) || !utf8.ValidString(rType) {
			requireUtilKind(t, err, cedar.KindInput)
			return
		}
		if pType == "User" && actionID == "view" && rType == "Photo" {
			if err != nil {
				t.Fatalf("fitting scope rejected: %v", err)
			}
			return
		}
		// Malformed type tokens fail principal/resource parsing; well-formed
		// ones miss the action's declared request environment.
		var ce *cedar.Error
		if !errors.As(err, &ce) ||
			(ce.Kind != cedar.KindRequest && ce.Kind != cedar.KindPrincipal && ce.Kind != cedar.KindResource) {
			t.Fatalf("scope %q/%q/%q: %v", pType, actionID, rType, err)
		}
	})
}
