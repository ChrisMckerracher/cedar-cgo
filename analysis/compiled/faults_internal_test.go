package compiled

import (
	"context"
	"errors"
	"strings"
	"testing"

	uids "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
)

func TestCompiledHostFaultOverridesCompileError(t *testing.T) {
	fault := errors.New("transport failed")
	s, _, transport := testSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		if _, err := native.CallbackFrom(ctx).Call(ctx, 3, []byte("query")); !errors.Is(err, fault) {
			t.Fatalf("callback failure: %v", err)
		}
		return []byte(`{"error":{"kind":"compile_a","message":"ill-typed"}}`), nil
	})
	transport.WriteError = fault
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); !errors.Is(err, fault) {
		t.Fatalf("host fault replaced by compile error: %v", err)
	}
	if transport.Closes.Load() != 1 {
		t.Fatal("host fault kept solver alive")
	}
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("host fault retained session: %v", err)
	}
}

func TestCompiledSharedDecoderFaultInvalidatesSession(t *testing.T) {
	for _, query := range []string{"equivalent", "implies"} {
		t.Run(query, func(t *testing.T) {
			s, _, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(`{"report":{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":false,"counterexample":{"request":{"principal":{"type":"User","id":"u"},"action":{"type":"Action","id":""},"resource":{"type":"Document","id":"d"},"context":{}},"entities":[],"a_decision":"allow","b_decision":"allow"}}]}}`), nil
			})
			s.environments = []RequestEnvironment{{PrincipalType: "User", Action: uids.NewEntityUID("Action", ""), ResourceType: "Document"}}
			handle := PolicySet{session: s, id: 1}
			if _, err := s.check(context.Background(), query, handle, handle); err == nil || !strings.Contains(err.Error(), "does not violate the property") {
				t.Fatalf("contradictory report reached the wrong guard: %v", err)
			}
			if transport.Closes.Load() != 1 {
				t.Fatal("shared decoder fault kept solver alive")
			}
			if _, err := s.check(context.Background(), query, handle, handle); !errors.Is(err, ErrClosed) {
				t.Fatalf("decoder fault retained session: %v", err)
			}
		})
	}
}

func TestCompiledCheckRequiresActionID(t *testing.T) {
	for _, action := range []string{`{"type":"Action"}`, `{"type":"Action","id":null}`, `{"type":"Action","id":""}`} {
		t.Run(action, func(t *testing.T) {
			s, instance, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(`{"report":{"results":[{"principal_type":"User","action":` + action + `,"resource_type":"Document","holds":true}]}}`), nil
			})
			s.environments = []RequestEnvironment{{PrincipalType: "User", Action: uids.NewEntityUID("Action", ""), ResourceType: "Document"}}
			handle := PolicySet{session: s, id: 1}
			report, err := s.Equivalent(context.Background(), handle, handle)
			if action == `{"type":"Action","id":""}` {
				if err != nil || !report.Holds() || transport.Closes.Load() != 0 || instance.closes.Load() != 0 {
					t.Fatalf("explicit empty action ID rejected: %+v %v", report, err)
				}
			} else if err == nil || transport.Closes.Load() != 1 || instance.closes.Load() != 1 {
				t.Fatalf("incomplete action ID retained session: %+v %v", report, err)
			}
		})
	}
}

func TestCompiledInputLimitLeavesSessionUsable(t *testing.T) {
	s, instance, transport := testSession(t, func(context.Context, []byte) ([]byte, error) { return []byte(`{"handle":2}`), nil })
	s.config.MaxSourceBytes = 1
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); err == nil {
		t.Fatal("source limit ignored")
	}
	if instance.calls.Load() != 0 || transport.Closes.Load() != 0 {
		t.Fatal("source limit changed session")
	}
	s.config.MaxSourceBytes = 1 << 20
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); err != nil {
		t.Fatal(err)
	}
}
