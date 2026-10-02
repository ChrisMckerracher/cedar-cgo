package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type formatCase struct {
	Name        string
	Input       string
	LineWidth   uint32 `json:"line_width"`
	IndentWidth int32  `json:"indent_width"`
	Valid       bool
	Contexts    []json.RawMessage
}

type formatExpected struct {
	Name      string
	Formatted *string
	Outcomes  []struct {
		Decision string
		Reasons  []string
		ErrorIDs []string `json:"error_ids"`
	}
}

func TestFormatNativeParity(t *testing.T) {
	var cases []formatCase
	var expected []formatExpected
	for path, into := range map[string]any{
		"../testdata/parity/format/cases.json":    &cases,
		"../testdata/parity/format/expected.json": &expected,
	} {
		if err := json.Unmarshal(readFile(t, path), into); err != nil {
			t.Fatal(err)
		}
	}
	if len(cases) != len(expected) || len(cases) == 0 {
		t.Fatalf("fixture counts: %d cases, %d results", len(cases), len(expected))
	}
	rt := testRuntime(t)
	for i, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			want := expected[i]
			if tc.Name != want.Name {
				t.Fatalf("fixture names differ: %q, %q", tc.Name, want.Name)
			}
			if (want.Formatted != nil) != tc.Valid {
				t.Fatalf("fixture validity changed for %s", tc.Name)
			}
			opts := []cedar.FormatOption{cedar.WithFormatLineWidth(tc.LineWidth), cedar.WithFormatIndentWidth(tc.IndentWidth)}
			formatted, err := rt.FormatPolicies(context.Background(), tc.Input, opts...)
			if want.Formatted == nil {
				requireFormatError(t, formatted, err, cedar.KindPolicies)
				return
			}
			if err != nil || formatted != *want.Formatted {
				t.Fatalf("Wasm %q, %v; native %q", formatted, err, *want.Formatted)
			}
			again, err := rt.FormatPolicies(context.Background(), formatted, opts...)
			if err != nil || again != formatted {
				t.Fatalf("not idempotent: %q, %v", again, err)
			}
			if len(want.Outcomes) != len(tc.Contexts) {
				t.Fatal("missing native outcomes")
			}
			var before []cedar.Response
			for _, source := range []string{tc.Input, formatted} {
				a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Policies: cedar.PoliciesFromCedar(source)})
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				var responses []cedar.Response
				for j, ctx := range tc.Contexts {
					resp, err := a.Authorize(context.Background(), simpleRequest(cedar.ContextFromJSON(ctx)))
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

func requireFormatError(t testing.TB, out string, err error, kind cedar.ErrorKind) {
	t.Helper()
	var e *cedar.Error
	if out != "" || !errors.As(err, &e) || e.Kind != kind {
		t.Fatalf("format = %q, %v; want empty output and %s", out, err, kind)
	}
}

func TestFormatDiagnosticsAndInput(t *testing.T) {
	rt := testRuntime(t)
	for _, text := range []string{
		"// café\npermit(principal, action, resource) when { 1 + };",
		`@id("one") @id("two") permit(principal, action, resource);`,
		`permit(principal, action, resource) when { principal == ?principal };`,
		"\x00",
	} {
		out, err := rt.FormatPolicies(context.Background(), text)
		requireFormatError(t, out, err, cedar.KindPolicies)
		if !strings.Contains(err.Error(), "bytes ") {
			t.Fatalf("diagnostic lost source span: %v", err)
		}
		if strings.HasPrefix(text, "// café") {
			offset := strings.IndexByte(text, '}')
			if !strings.Contains(err.Error(), fmt.Sprintf("bytes %d..%d", offset, offset+1)) {
				t.Fatalf("diagnostic did not preserve UTF-8 byte offset: %v", err)
			}
		}
	}
	for _, text := range []string{"\xff", "//\xc0\x80", `@id("` + "\xed\xa0\x80" + `") permit(principal,action,resource);`} {
		out, err := rt.FormatPolicies(context.Background(), text)
		requireFormatError(t, out, err, cedar.KindInput)
	}
	for _, opts := range [][]cedar.FormatOption{
		{nil}, {cedar.WithFormatMaxOutputBytes(0)}, {cedar.WithFormatMaxOutputBytes(-1)},
		{cedar.WithFormatMaxOutputBytes(cedar.DefaultMaxResponseBytes + 1)},
	} {
		out, err := rt.FormatPolicies(context.Background(), permitAll.Text(), opts...)
		requireFormatError(t, out, err, cedar.KindInput)
	}
}

func TestFormatOutputLimit(t *testing.T) {
	rt := testRuntime(t)
	const input = `// café` + "\n" + `permit(principal,action,resource);`
	want, err := rt.FormatPolicies(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := rt.FormatPolicies(context.Background(), input, cedar.WithFormatMaxOutputBytes(len(want)-1))
	requireFormatError(t, out, err, cedar.KindLimit)
	out, err = rt.FormatPolicies(context.Background(), input, cedar.WithFormatMaxOutputBytes(len(want)))
	if err != nil || out != want {
		t.Fatalf("exact byte limit: %q, %v", out, err)
	}
}

func TestFormatCancellationAndIsolation(t *testing.T) {
	rt := testRuntime(t)
	a, err := rt.NewAuthorizer(context.Background(), cedar.Config{Policies: permitAll, Limits: cedar.Limits{MaxInstances: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := rt.FormatPolicies(ctx, permitAll.Text())
	if out != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled format: %q, %v", out, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err = rt.FormatPolicies(ctx, strings.Repeat(permitAll.Text()+"\n", 20000))
	if out != "" || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("deadline format: %q, %v, elapsed %v", out, err, time.Since(start))
	}
	out, err = rt.FormatPolicies(context.Background(), permitAll.Text())
	if err != nil || out != "permit (principal, action, resource);\n" {
		t.Fatalf("format after cancellation: %q, %v", out, err)
	}
	resp, err := a.Authorize(context.Background(), simpleRequest(cedar.Context{}))
	if err != nil || resp.Decision != cedar.Allow || a.Stats().Created != 1 {
		t.Fatalf("format disturbed authorizer: %+v, %v, %+v", resp, err, a.Stats())
	}
}

func TestFormatMemoryAndStackLimits(t *testing.T) {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx, cedar.WithMemoryLimit(16<<20), cedar.WithCompilationCache(testCache))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	out, err := rt.FormatPolicies(ctx, "//"+strings.Repeat("x", 4<<20))
	requireFormatError(t, out, err, cedar.KindFault)
	timed, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	out, err = rt.FormatPolicies(timed, `permit(principal,action,resource)when{true};`,
		cedar.WithFormatLineWidth(1), cedar.WithFormatIndentWidth(math.MaxInt32))
	requireFormatError(t, out, err, cedar.KindFault)
	out, err = rt.FormatPolicies(ctx, permitAll.Text())
	if err != nil || out == "" {
		t.Fatalf("format after memory fault: %q, %v", out, err)
	}
	deep := "permit(principal,action,resource)when{" + strings.Repeat("(", 800) + "true" + strings.Repeat(")", 800) + "};"
	out, err = testRuntime(t).FormatPolicies(ctx, deep)
	requireFormatError(t, out, err, cedar.KindFault)
	out, err = testRuntime(t).FormatPolicies(ctx, permitAll.Text())
	if err != nil || out == "" {
		t.Fatalf("format after stack fault: %q, %v", out, err)
	}
}

func TestFormatConcurrent(t *testing.T) {
	rt := testRuntime(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			out, err := rt.FormatPolicies(context.Background(), permitAll.Text(), cedar.WithFormatLineWidth(math.MaxUint32))
			if err != nil || out != "permit (principal, action, resource);\n" {
				t.Errorf("concurrent format: %q, %v", out, err)
			}
		})
	}
	wg.Wait()
}

func ExampleRuntime_FormatPolicies() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	text, err := rt.FormatPolicies(ctx, `permit(principal,action,resource)when{context.mfa};`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(text)
	// Output:
	// permit (principal, action, resource)
	// when { context.mfa };
}
