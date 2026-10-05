package source_test

import (
	context "context"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	policysource "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/source"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"
	reflect "reflect"
	strings "strings"
	testing "testing"
	time "time"
	utf8 "unicode/utf8"
)

func TestSourceTokensPreserveCommentsAndSpacing(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	source := "// leading 雪  \r\n@note(\"😀\") // annotation\r\npermit( principal == User::\"old\", action, resource ); // inline  \r\n// end  \r\n"
	tokens, err := rt.Source().TokenizePolicies(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := testsupport.ReconstructTokenSource(source, tokens); got != source {
		t.Fatalf("source changed: %q", got)
	}
	if !reflect.DeepEqual(tokens.Tokens[0].LeadingComments, []string{"// leading 雪"}) || !reflect.DeepEqual(tokens.TrailingComments, []string{"// end"}) {
		t.Fatalf("native comment summaries: %+v", tokens)
	}
	var edit *policysource.SourceToken
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
	parsed, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromCedar(changed))
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := parsed.Policy("policy0")
	if !ok || policy.Annotations()["note"] != "😀" {
		t.Fatal("edit changed the annotation")
	}
	reparsed, err := rt.Policies().ParsePolicySet(ctx, parsed.Source())
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []cedarpolicy.PolicySet{cedarpolicy.PoliciesFromCedar(changed), reparsed.Source()} {
		authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: set})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"old", "new"} {
			response, err := authorizer.Authorize(ctx, cedarrequest.Request{Principal: entityuid.NewEntityUID("User", id), Action: entityuid.NewEntityUID("Action", "view"), Resource: entityuid.NewEntityUID("Photo", "p")})
			want := cedarrequest.Deny
			if id == "new" {
				want = cedarrequest.Allow
			}
			if err != nil || response.Decision != want {
				t.Fatalf("source/JSON semantic result for %s: %+v %v", id, response, err)
			}
		}
		authorizer.Close()
	}
	changedTokens, err := rt.Source().TokenizePolicies(ctx, changed)
	if err != nil || testsupport.ReconstructTokenSource(changed, changedTokens) != changed {
		t.Fatalf("edited source reconstruction: %+v %v", changedTokens, err)
	}
}

func TestSourceTokensSeparateLexingFromValidation(t *testing.T) {
	rt := testsupport.TestRuntime(t)
	ctx := context.Background()
	tokens, err := rt.Source().TokenizePolicies(ctx, "permit(")
	if err != nil || len(tokens.Tokens) != 2 {
		t.Fatalf("lexically valid incomplete source: %+v %v", tokens, err)
	}
	if _, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromCedar("permit(")); err == nil {
		t.Fatal("incomplete policy passed semantic parsing")
	}
	tokens, err = rt.Source().TokenizePolicies(ctx, "permit $")
	var ce *diagnostic.Error
	if !errors.As(err, &ce) || ce.Kind != diagnostic.KindPolicies || !reflect.DeepEqual(tokens, policysource.SourceTokens{}) {
		t.Fatalf("invalid lexical source: %+v %v", tokens, err)
	}
}

func FuzzSourceTokenSpans(f *testing.F) {
	rt := testsupport.TestRuntime(f)
	for _, source := range []string{"", "// 雪\r\n", `permit(principal, action, resource);`, "// leading\n@note(\"😀\") permit(principal == ?principal, action, resource); // end", "permit $", string([]byte{0xff})} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 4096 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tokens, err := rt.Source().TokenizePolicies(ctx, source)
		if err != nil {
			var ce *diagnostic.Error
			if !errors.As(err, &ce) || (ce.Kind != diagnostic.KindInput && ce.Kind != diagnostic.KindPolicies) || !reflect.DeepEqual(tokens, policysource.SourceTokens{}) {
				t.Fatalf("unexpected lexer failure: %+v %v", tokens, err)
			}
			if !utf8.ValidString(source) && ce.Kind != diagnostic.KindInput {
				t.Fatal("invalid UTF-8 entered the lexer")
			}
			return
		}
		if !utf8.ValidString(source) || testsupport.ReconstructTokenSource(source, tokens) != source {
			t.Fatal("token spans changed the original source")
		}
	})
}
