package cedar_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func reconstructTokenSource(source string, tokens cedar.SourceTokens) string {
	var result strings.Builder
	var previous uint32
	for _, token := range tokens.Tokens {
		result.WriteString(source[previous:token.Span.Start])
		result.WriteString(token.Text)
		previous = token.Span.End
	}
	result.WriteString(source[previous:])
	return result.String()
}

func TestSourceTokensPreserveCommentsAndSpacing(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	source := "// leading 雪  \r\n@note(\"😀\") // annotation\r\npermit( principal == User::\"old\", action, resource ); // inline  \r\n// end  \r\n"
	tokens, err := rt.TokenizePolicies(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := reconstructTokenSource(source, tokens); got != source {
		t.Fatalf("source changed: %q", got)
	}
	if !reflect.DeepEqual(tokens.Tokens[0].LeadingComments, []string{"// leading 雪"}) || !reflect.DeepEqual(tokens.TrailingComments, []string{"// end"}) {
		t.Fatalf("native comment summaries: %+v", tokens)
	}
	var edit *cedar.SourceToken
	for i := range tokens.Tokens {
		token := &tokens.Tokens[i]
		if token.Text == `"😀"` && int(token.Span.Start) != strings.Index(source, `"😀"`) {
			t.Fatal("Unicode span uses character offsets instead of byte offsets")
		}
		if token.Kind == "string" && token.Text == `"old"` {
			edit = token
		}
	}
	if edit == nil {
		t.Fatal("entity ID token is absent")
	}
	changed := source[:edit.Span.Start] + `"new"` + source[edit.Span.End:]
	if strings.Replace(changed, `"new"`, `"old"`, 1) != source {
		t.Fatal("token edit changed comments or spacing")
	}
	parsed, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromCedar(changed))
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := parsed.Policy("policy0")
	if !ok || policy.Annotations()["note"] != "😀" {
		t.Fatal("edit changed the annotation")
	}
	reparsed, err := rt.ParsePolicySet(ctx, parsed.Source())
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []cedar.PolicySet{cedar.PoliciesFromCedar(changed), reparsed.Source()} {
		authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: set})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"old", "new"} {
			response, err := authorizer.Authorize(ctx, cedar.Request{Principal: cedar.NewEntityUID("User", id), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "p")})
			want := cedar.Deny
			if id == "new" {
				want = cedar.Allow
			}
			if err != nil || response.Decision != want {
				t.Fatalf("source/JSON semantic result for %s: %+v %v", id, response, err)
			}
		}
		authorizer.Close()
	}
	changedTokens, err := rt.TokenizePolicies(ctx, changed)
	if err != nil || reconstructTokenSource(changed, changedTokens) != changed {
		t.Fatalf("edited source reconstruction: %+v %v", changedTokens, err)
	}
}

func TestSourceTokensSeparateLexingFromValidation(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	tokens, err := rt.TokenizePolicies(ctx, "permit(")
	if err != nil || len(tokens.Tokens) != 2 {
		t.Fatalf("lexically valid incomplete source: %+v %v", tokens, err)
	}
	if _, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromCedar("permit(")); err == nil {
		t.Fatal("incomplete policy passed semantic parsing")
	}
	tokens, err = rt.TokenizePolicies(ctx, "permit $")
	var ce *cedar.Error
	if !errors.As(err, &ce) || ce.Kind != cedar.KindPolicies || !reflect.DeepEqual(tokens, cedar.SourceTokens{}) {
		t.Fatalf("invalid lexical source: %+v %v", tokens, err)
	}
}

func FuzzSourceTokenSpans(f *testing.F) {
	rt := testRuntime(f)
	for _, source := range []string{"", "// 雪\r\n", `permit(principal, action, resource);`, "// leading\n@note(\"😀\") permit(principal == ?principal, action, resource); // end", "permit $", string([]byte{0xff})} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 4096 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tokens, err := rt.TokenizePolicies(ctx, source)
		if err != nil {
			var ce *cedar.Error
			if !errors.As(err, &ce) || (ce.Kind != cedar.KindInput && ce.Kind != cedar.KindPolicies) || !reflect.DeepEqual(tokens, cedar.SourceTokens{}) {
				t.Fatalf("unexpected lexer failure: %+v %v", tokens, err)
			}
			if !utf8.ValidString(source) && ce.Kind != cedar.KindInput {
				t.Fatal("invalid UTF-8 entered the lexer")
			}
			return
		}
		if !utf8.ValidString(source) || reconstructTokenSource(source, tokens) != source {
			t.Fatal("token spans changed the original source")
		}
	})
}
