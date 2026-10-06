package compiled

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
)

func TestCompiledProtocolFaultsAndOrdinaryErrors(t *testing.T) {
	for _, response := range []string{`not JSON`, `{"report":{}}`, `{"error":{"kind":"solver","message":"closed"}}`, `{"error":{"kind":"unconfirmed_counterexample","message":"false model"}}`, `{"error":{"kind":"input"}}`, `{"error":{"kind":"input","message":null}}`, `{"error":{"kind":"input","message":""}}`, `{"handle":1}`} {
		t.Run(response, func(t *testing.T) {
			s, _, transport := testSession(t, func(context.Context, []byte) ([]byte, error) { return []byte(response), nil })
			if _, err := s.Compile(context.Background(), policy.PolicySet{}); err == nil {
				t.Fatal("invalid response accepted")
			}
			if transport.Closes.Load() != 1 {
				t.Fatal("fault did not close solver")
			}
		})
	}
	s, _, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
		return []byte(`{"error":{"kind":"compile_a","message":"ill-typed"}}`), nil
	})
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); err == nil {
		t.Fatal("compile failure omitted")
	}
	if transport.Closes.Load() != 0 {
		t.Fatal("ordinary compile failure invalidated session")
	}
}

func TestCompiledRejectsMixedResponseEnvelopes(t *testing.T) {
	for _, response := range []string{
		`{"handle":2,"error":{"kind":"compile_a","message":"ill-typed"}}`,
		`{"handle":2,"error":null}`,
		`{"handle":2,"released":true}`,
		`{"error":{"kind":"input","message":"invalid input"},"environments":[]}`,
	} {
		t.Run(response, func(t *testing.T) {
			s, instance, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(response), nil
			})
			if _, err := s.Compile(context.Background(), policy.PolicySet{}); err == nil || !strings.Contains(err.Error(), "invalid envelope") {
				t.Fatalf("mixed response error: %v", err)
			}
			if transport.Closes.Load() != 1 || instance.closes.Load() != 1 {
				t.Fatal("mixed response retained resources")
			}
			if _, err := s.Compile(context.Background(), policy.PolicySet{}); !errors.Is(err, ErrClosed) {
				t.Fatalf("mixed response retained session: %v", err)
			}
		})
	}
}

func TestCompiledRejectsNestedReportErrors(t *testing.T) {
	for _, record := range []string{`{"kind":"solver","message":"broken solver"}`, `{}`, `null`} {
		t.Run(record, func(t *testing.T) {
			s, instance, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(`{"report":{"results":[],"error":` + record + `}}`), nil
			})
			h := PolicySet{session: s, id: 1}
			if _, err := s.Equivalent(context.Background(), h, h); err == nil || !strings.Contains(err.Error(), "compiled report has an invalid envelope") {
				t.Fatalf("nested error report accepted: %v", err)
			}
			if transport.Closes.Load() != 1 || instance.closes.Load() != 1 {
				t.Fatal("nested report error retained resources")
			}
			if _, err := s.Equivalent(context.Background(), h, h); !errors.Is(err, ErrClosed) {
				t.Fatalf("nested report error retained session: %v", err)
			}
		})
	}
}

func TestCompiledRejectsInvalidUTF8Response(t *testing.T) {
	s, instance, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
		response := append([]byte(`{"error":{"kind":"input","message":"`), byte(0xff))
		return append(response, []byte(`"}}`)...), nil
	})
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("invalid UTF-8 response error: %v", err)
	}
	if transport.Closes.Load() != 1 || instance.closes.Load() != 1 {
		t.Fatal("invalid UTF-8 response retained resources")
	}
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("invalid UTF-8 response retained session: %v", err)
	}
}

func TestCompiledValidOrdinaryErrorsPreserveSession(t *testing.T) {
	for _, kind := range []string{"input", "compile_a"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			s, instance, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
				if calls.Add(1) == 1 {
					return []byte(`{"error":{"kind":"` + kind + `","message":"invalid policy"}}`), nil
				}
				return []byte(`{"handle":2}`), nil
			})
			var input *report.Error
			if _, err := s.Compile(context.Background(), policy.PolicySet{}); !errors.As(err, &input) || input.Kind != kind {
				t.Fatalf("ordinary error changed: %v", err)
			}
			if _, err := s.Compile(context.Background(), policy.PolicySet{}); err != nil {
				t.Fatalf("ordinary error prevented later compilation: %v", err)
			}
			if transport.Closes.Load() != 0 || instance.closes.Load() != 0 {
				t.Fatal("ordinary error closed resources")
			}
		})
	}
}
