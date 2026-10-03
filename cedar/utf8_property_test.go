package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"unicode"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// propGenUnicode draws valid UTF-8 from edge runes and broad script tables.
// U+FFFD must keep its identity without normalization; NUL and quotes stress
// JSON escaping, which still preserves identity bytes.
var propGenUnicode = rapid.StringOfN(
	rapid.RuneFrom([]rune{0, '\ufffd', '\U0001f600', '雪', 'a', '"', '\\', '\n'}, unicode.L, unicode.M),
	0, 8, 64,
)

// propGenMalformed turns valid text into invalid UTF-8 through four strategies:
// a stray continuation byte, a never-valid byte, a truncated trailing rune, and
// a surrogate sequence. Every strategy yields invalid UTF-8 for any input.
func propGenMalformed(t *rapid.T, text string) string {
	t.Helper()
	b := []byte(text)
	var out []byte
	switch rapid.IntRange(0, 3).Draw(t, "corruption") {
	case 0:
		at := rapid.IntRange(0, len(b)).Draw(t, "at")
		stray := byte(0x80 + rapid.IntRange(0, 0x3f).Draw(t, "stray"))
		out = append(append(append([]byte{}, b[:at]...), stray), b[at:]...)
	case 1:
		never := byte(0xfe + rapid.IntRange(0, 1).Draw(t, "never"))
		out = append(append([]byte{}, b...), never)
	case 2:
		// Truncate the final byte of a multibyte trailing rune; ASCII endings
		// fall back to the never-valid byte so the result is always malformed.
		if _, size := utf8.DecodeLastRune(b); size > 1 {
			out = b[:len(b)-1]
		} else {
			out = append(append([]byte{}, b...), 0xff)
		}
	default:
		at := rapid.IntRange(0, len(b)).Draw(t, "at")
		out = append(append([]byte{}, b[:at]...), 0xed, 0xa0, 0x80)
		out = append(out, b[at:]...)
	}
	if utf8.Valid(out) {
		t.Fatalf("corruption strategy produced valid UTF-8: %q -> %q", text, out)
	}
	return string(out)
}

func propRequireUTF8InputError(pt *rapid.T, err error) {
	pt.Helper()
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindInput {
		pt.Fatalf("got %v; want KindInput", err)
	}
}

// Valid Unicode never errors at the boundary and marshals without changing
// identity bytes for UIDs, strings, record keys, and nested containers.
func TestPropertyUnicodeValuesPreserveIdentity(t *testing.T) {
	rapid.Check(t, func(pt *rapid.T) {
		text := propGenUnicode.Draw(pt, "text")
		uid := cedar.NewEntityUID(text, text)
		values := []any{
			uid, cedar.String(text), cedar.Record{text: uid},
			cedar.Set{uid, cedar.String(text)}, cedar.Decimal(text), cedar.IPAddr(text),
			cedar.Datetime(text), cedar.Duration(text),
			cedar.KnownEntityUID(uid), cedar.UnknownEntityUID(text),
			cedar.Entity{UID: uid, Parents: []cedar.EntityUID{uid}, Attrs: cedar.Record{text: cedar.String(text)}},
		}
		for _, value := range values {
			if _, err := json.Marshal(value); err != nil {
				pt.Fatalf("valid text %q rejected for %T: %v", text, value, err)
			}
		}
		var decoded map[string]struct {
			Entity struct{ Type, ID string } `json:"__entity"`
		}
		encoded, err := json.Marshal(cedar.Record{text: uid})
		if err != nil {
			pt.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			pt.Fatal(err)
		}
		got, ok := decoded[text]
		if !ok || got.Entity.Type != text || got.Entity.ID != text {
			pt.Fatalf("identity changed: %s", encoded)
		}
	})
}

// Malformed UTF-8 is rejected for every value shape, including nested ones.
func TestPropertyMalformedUTF8ValuesRejected(t *testing.T) {
	rapid.Check(t, func(pt *rapid.T) {
		bad := propGenMalformed(pt, propGenUnicode.Draw(pt, "text"))
		uid := cedar.NewEntityUID(bad, "a")
		cases := map[string]any{
			"UID ID":         uid,
			"UID type":       cedar.NewEntityUID(bad, "a"),
			"string":         cedar.String(bad),
			"extension arg":  cedar.Decimal(bad),
			"record key":     cedar.Record{bad: cedar.Bool(true)},
			"nested set":     cedar.Set{cedar.Record{"a": cedar.Set{cedar.String(bad)}}},
			"entity parents": cedar.Entity{UID: cedar.NewEntityUID("User", "a"), Parents: []cedar.EntityUID{uid}},
		}
		for name, value := range cases {
			if _, err := json.Marshal(value); err == nil {
				pt.Fatalf("%s: malformed %q encoded without an error", name, bad)
			}
		}
	})
}

// Malformed UTF-8 fails closed before instance acquisition in every request
// mode, no matter which request field carries it.
func TestPropertyMalformedUTF8RequestsFailClosed(t *testing.T) {
	ctx := context.Background()
	rt := testRuntime(t)
	schema := cedar.SchemaFromCedar(`entity User; entity Photo; action view appliesTo {principal: User, resource: Photo, context: {}};`)
	a, err := rt.NewAuthorizer(ctx, cedar.Config{
		Schema:   &schema,
		Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource);`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	rapid.Check(t, func(pt *rapid.T) {
		bad := propGenMalformed(pt, propGenUnicode.Draw(pt, "text"))
		req := cedar.Request{
			Principal: cedar.NewEntityUID("User", "u"),
			Action:    cedar.NewEntityUID("Action", "view"),
			Resource:  cedar.NewEntityUID("Photo", "p"),
		}
		field := rapid.SampledFrom([]string{
			"principalType", "principalID", "actionType", "actionID", "resourceType", "resourceID",
			"contextValue", "contextKey", "rawContext", "entities", "rawEntities",
		}).Draw(pt, "field")
		switch field {
		case "principalType":
			req.Principal.Type = bad
		case "principalID":
			req.Principal.ID = bad
		case "actionType":
			req.Action.Type = bad
		case "actionID":
			req.Action.ID = bad
		case "resourceType":
			req.Resource.Type = bad
		case "resourceID":
			req.Resource.ID = bad
		case "contextValue":
			req.Context = cedar.NewContext(cedar.Record{"a": cedar.String(bad)})
		case "contextKey":
			req.Context = cedar.NewContext(cedar.Record{bad: cedar.Bool(true)})
		case "rawContext":
			req.Context = cedar.ContextFromJSON([]byte(`{"a":"` + bad + `"}`))
		case "entities":
			req.Entities = cedar.NewEntities(cedar.Entity{UID: cedar.NewEntityUID("User", bad)})
		case "rawEntities":
			req.Entities = cedar.EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))
		}
		partial := cedar.PartialRequest{
			Principal: cedar.KnownEntityUID(req.Principal),
			Action:    req.Action,
			Resource:  cedar.KnownEntityUID(req.Resource),
			Context:   &req.Context,
		}
		if field == "entities" || field == "rawEntities" {
			// Mirror the malformed store into the partial leg so every field
			// exercises the same rejection path.
			partial.Entities = cedar.NewPartialEntities(cedar.PartialEntity{UID: cedar.NewEntityUID("User", bad)})
		}

		resp, aerr := a.Authorize(ctx, req)
		if resp.Decision != cedar.Deny {
			pt.Fatal("malformed request allowed")
		}
		propRequireUTF8InputError(pt, aerr)
		called := false
		loader := cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			called = true
			return cedar.EntityLoadResult{}, nil
		})
		decision, berr := a.AuthorizeBatched(ctx, req, loader, cedar.BatchedOptions{MaxIterations: 1})
		if decision != cedar.Deny || called {
			pt.Fatalf("malformed batched request: %v loaderCalled=%v", decision, called)
		}
		propRequireUTF8InputError(pt, berr)
		presp, perr := a.PartialAuthorize(ctx, partial)
		if presp.Decision != cedar.Undecided {
			pt.Fatal("malformed partial request decided")
		}
		propRequireUTF8InputError(pt, perr)
	})
}
