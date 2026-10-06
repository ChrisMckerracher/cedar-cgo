package format_test

import (
	context "context"
	json "encoding/json"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	policyformat "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/format"
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	reflect "reflect"
	strings "strings"
	testing "testing"
)

func TestFormatNativeParity(t *testing.T) {
	var cases []FormatCase
	var expected []FormatExpected
	for path, into := range map[string]any{
		"../testdata/parity/format/cases.json":    &cases,
		"../testdata/parity/format/expected.json": &expected,
	} {
		if err := json.Unmarshal(fixture.MustReadFile(t, path), into); err != nil {
			t.Fatal(err)
		}
	}
	if len(cases) != len(expected) || len(cases) == 0 {
		t.Fatalf("fixture counts: %d cases, %d results", len(cases), len(expected))
	}
	rt := testruntime.New(t)
	for i, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			want := expected[i]
			if tc.Name != want.Name {
				t.Fatalf("fixture names differ: %q, %q", tc.Name, want.Name)
			}
			if (want.Formatted != nil) != tc.Valid {
				t.Fatalf("fixture validity changed for %s", tc.Name)
			}
			opts := []policyformat.FormatOption{policyformat.WithFormatLineWidth(tc.LineWidth), policyformat.WithFormatIndentWidth(tc.IndentWidth)}
			formatted, err := rt.Formatter().FormatPolicies(context.Background(), tc.Input, opts...)
			if want.Formatted == nil {
				RequireFormatError(t, formatted, err, diagnostic.KindPolicies)
				return
			}
			if err != nil || formatted != *want.Formatted {
				t.Fatalf("Go %q, %v; native %q", formatted, err, *want.Formatted)
			}
			again, err := rt.Formatter().FormatPolicies(context.Background(), formatted, opts...)
			if err != nil || again != formatted {
				t.Fatalf("not idempotent: %q, %v", again, err)
			}
			if len(want.Outcomes) != len(tc.Contexts) {
				t.Fatal("missing native outcomes")
			}
			var before []cedarrequest.Response
			for _, source := range []string{tc.Input, formatted} {
				a, err := rt.NewAuthorizer(context.Background(), authorization.Config{Policies: cedarpolicy.PoliciesFromCedar(source)})
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				var responses []cedarrequest.Response
				for j, ctx := range tc.Contexts {
					resp, err := a.Authorize(context.Background(), fault.SimpleRequest(cedarrequest.ContextFromJSON(ctx)))
					if err != nil {
						t.Fatal(err)
					}
					native := want.Outcomes[j]
					errorIDs := make([]string, 0, len(resp.Errors))
					for _, diagnostic := range resp.Errors {
						errorIDs = append(errorIDs, diagnostic.PolicyID)
					}
					if resp.Decision.String() != native.Decision || !reflect.DeepEqual(resp.Reasons, native.Reasons) || !reflect.DeepEqual(errorIDs, native.ErrorIDs) {
						t.Fatalf("authorization %+v differs from native %+v", resp, native)
					}
					responses = append(responses, resp)
				}
				if before != nil && !reflect.DeepEqual(before, responses) {
					t.Fatalf("formatting changed authorization: before %+v, after %+v", before, responses)
				}
				before = responses
			}
		})
	}
}

func TestFormatDiagnosticsAndInput(t *testing.T) {
	rt := testruntime.New(t)
	for _, TextValue := range []string{
		"// café\npermit(principal, action, resource) when { 1 + };",
		`@id("one") @id("two") permit(principal, action, resource);`,
		`permit(principal, action, resource) when { principal == ?principal };`,
		"\x00",
	} {
		out, err := rt.Formatter().FormatPolicies(context.Background(), TextValue)
		RequireFormatError(t, out, err, diagnostic.KindPolicies)
		if !strings.Contains(err.Error(), "bytes ") {
			t.Fatalf("diagnostic lost source span: %v", err)
		}
		if strings.HasPrefix(TextValue, "// café") {
			offset := strings.IndexByte(TextValue, '}')
			if !strings.Contains(err.Error(), fmt.Sprintf("bytes %d..%d", offset, offset+1)) {
				t.Fatalf("diagnostic did not preserve UTF-8 byte offset: %v", err)
			}
		}
	}
	for _, TextValue := range []string{"\xff", "//\xc0\x80", `@id("` + "\xed\xa0\x80" + `") permit(principal,action,resource);`} {
		out, err := rt.Formatter().FormatPolicies(context.Background(), TextValue)
		RequireFormatError(t, out, err, diagnostic.KindInput)
	}
	for _, opts := range [][]policyformat.FormatOption{
		{nil}, {policyformat.WithFormatMaxOutputBytes(0)}, {policyformat.WithFormatMaxOutputBytes(-1)},
		{policyformat.WithFormatMaxOutputBytes(cedar.DefaultMaxResponseBytes + 1)},
	} {
		out, err := rt.Formatter().FormatPolicies(context.Background(), fault.PermitAll.Text(), opts...)
		RequireFormatError(t, out, err, diagnostic.KindInput)
	}
}
