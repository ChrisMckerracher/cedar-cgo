package analysis

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type compiledTestTransport struct {
	closed chan struct{}
	once   sync.Once
	closes atomic.Int32
}

type compiledTestSolver func(context.Context) (Session, error)

func (start compiledTestSolver) Start(ctx context.Context) (Session, error) { return start(ctx) }

func (s *compiledTestTransport) Read([]byte) (int, error)       { <-s.closed; return 0, io.EOF }
func (s *compiledTestTransport) Write(data []byte) (int, error) { return len(data), nil }
func (s *compiledTestTransport) Close() error {
	s.once.Do(func() { s.closes.Add(1); close(s.closed) })
	return nil
}

type compiledTestInstance struct {
	calls  atomic.Int32
	closes atomic.Int32
	call   func(context.Context, []byte) ([]byte, error)
}

func (i *compiledTestInstance) Call(ctx context.Context, _ string, input []byte, _ uint32) ([]byte, error) {
	i.calls.Add(1)
	return i.call(ctx, input)
}
func (i *compiledTestInstance) Close(context.Context) error { i.closes.Add(1); return nil }

func testCompiledSession(t *testing.T, call func(context.Context, []byte) ([]byte, error)) (*CompiledSession, *compiledTestInstance, *compiledTestTransport) {
	t.Helper()
	lifetime, cancel := context.WithCancel(context.Background())
	transport := &compiledTestTransport{closed: make(chan struct{})}
	instance := &compiledTestInstance{call: call}
	a := &Analyzer{maxSourceBytes: 1 << 20, maxSolverOutput: 1 << 20, sessions: make(map[*CompiledSession]struct{})}
	s := &CompiledSession{analyzer: a, lifetime: lifetime, cancel: cancel, gate: make(chan struct{}, 1), done: make(chan struct{}), abortDone: make(chan struct{}), transport: transport, instance: instance, handles: map[uint64]struct{}{1: {}}, lastHandle: 1, environments: []RequestEnvironment{}}
	a.sessions[s] = struct{}{}
	t.Cleanup(func() { _ = s.Close() })
	return s, instance, transport
}

func TestCompiledQueuedCancellationPreservesActiveCall(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	s, instance, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
		close(entered)
		<-finish
		return []byte(`{"report":{"results":[]}}`), nil
	})
	handle := CompiledPolicySet{session: s, id: 1}
	active := make(chan error, 1)
	go func() { _, err := s.Equivalent(context.Background(), handle, handle); active <- err }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	queued := make(chan error, 1)
	go func() { _, err := s.Equivalent(ctx, handle, handle); queued <- err }()
	cancel()
	if err := <-queued; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued error %v", err)
	}
	if transport.closes.Load() != 0 || instance.calls.Load() != 1 {
		t.Fatal("queued cancellation interrupted active resources")
	}
	close(finish)
	if err := <-active; err != nil {
		t.Fatal(err)
	}
	if transport.closes.Load() != 0 {
		t.Fatal("successful active call closed solver")
	}
}

func TestCompiledActiveCancellationUnblocksSolverRead(t *testing.T) {
	entered := make(chan struct{})
	s, instance, transport := testCompiledSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		close(entered)
		state := ctx.Value(sessionKey{}).(*sessionState)
		_, err := state.session.Read(make([]byte, 1))
		return nil, err
	})
	handle := CompiledPolicySet{session: s, id: 1}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := s.Equivalent(ctx, handle, handle); result <- err }()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active error %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not unblock solver read")
	}
	if transport.closes.Load() != 1 || instance.closes.Load() != 1 {
		t.Fatal("active cancellation did not release both resources")
	}
	if _, err := s.Equivalent(context.Background(), handle, handle); !errors.Is(err, ErrCompiledClosed) {
		t.Fatalf("faulted session reused %v", err)
	}
}

func TestCompiledActiveTimeoutInvalidatesSession(t *testing.T) {
	s, _, transport := testCompiledSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		state := ctx.Value(sessionKey{}).(*sessionState)
		_, err := state.session.Read(make([]byte, 1))
		return nil, err
	})
	s.analyzer.timeout = 10 * time.Millisecond
	handle := CompiledPolicySet{session: s, id: 1}
	if _, err := s.Equivalent(context.Background(), handle, handle); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error %v", err)
	}
	if transport.closes.Load() != 1 {
		t.Fatal("timeout kept solver open")
	}
}

func TestCompiledProtocolFaultsAndOrdinaryErrors(t *testing.T) {
	for _, response := range []string{`not JSON`, `{"report":{}}`, `{"error":{"kind":"solver","message":"closed"}}`, `{"error":{"kind":"unconfirmed_counterexample","message":"false model"}}`, `{"error":{"kind":"input"}}`, `{"error":{"kind":"input","message":null}}`, `{"error":{"kind":"input","message":""}}`, `{"handle":1}`} {
		t.Run(response, func(t *testing.T) {
			s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) { return []byte(response), nil })
			if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err == nil {
				t.Fatal("invalid response accepted")
			}
			if transport.closes.Load() != 1 {
				t.Fatal("fault did not close solver")
			}
		})
	}
	s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
		return []byte(`{"error":{"kind":"compile_a","message":"ill-typed"}}`), nil
	})
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err == nil {
		t.Fatal("compile failure omitted")
	}
	if transport.closes.Load() != 0 {
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
			s, instance, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(response), nil
			})
			if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err == nil || !strings.Contains(err.Error(), "invalid envelope") {
				t.Fatalf("mixed response error: %v", err)
			}
			if transport.closes.Load() != 1 || instance.closes.Load() != 1 {
				t.Fatal("mixed response retained resources")
			}
			if _, err := s.Compile(context.Background(), cedar.PolicySet{}); !errors.Is(err, ErrCompiledClosed) {
				t.Fatalf("mixed response retained session: %v", err)
			}
		})
	}
}

func TestCompiledRejectsNestedReportErrors(t *testing.T) {
	for _, record := range []string{`{"kind":"solver","message":"broken solver"}`, `{}`, `null`} {
		t.Run(record, func(t *testing.T) {
			s, instance, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(`{"report":{"results":[],"error":` + record + `}}`), nil
			})
			h := CompiledPolicySet{session: s, id: 1}
			if _, err := s.Equivalent(context.Background(), h, h); err == nil || !strings.Contains(err.Error(), "compiled report has an invalid envelope") {
				t.Fatalf("nested error report accepted: %v", err)
			}
			if transport.closes.Load() != 1 || instance.closes.Load() != 1 {
				t.Fatal("nested report error retained resources")
			}
			if _, err := s.Equivalent(context.Background(), h, h); !errors.Is(err, ErrCompiledClosed) {
				t.Fatalf("nested report error retained session: %v", err)
			}
		})
	}
}

func TestCompiledRejectsInvalidUTF8Response(t *testing.T) {
	s, instance, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
		response := append([]byte(`{"error":{"kind":"input","message":"`), byte(0xff))
		return append(response, []byte(`"}}`)...), nil
	})
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("invalid UTF-8 response error: %v", err)
	}
	if transport.closes.Load() != 1 || instance.closes.Load() != 1 {
		t.Fatal("invalid UTF-8 response retained resources")
	}
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); !errors.Is(err, ErrCompiledClosed) {
		t.Fatalf("invalid UTF-8 response retained session: %v", err)
	}
}

func TestCompiledValidOrdinaryErrorsPreserveSession(t *testing.T) {
	for _, kind := range []string{"input", "compile_a"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			s, instance, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				if calls.Add(1) == 1 {
					return []byte(`{"error":{"kind":"` + kind + `","message":"invalid policy"}}`), nil
				}
				return []byte(`{"handle":2}`), nil
			})
			var input *Error
			if _, err := s.Compile(context.Background(), cedar.PolicySet{}); !errors.As(err, &input) || input.Kind != kind {
				t.Fatalf("ordinary error changed: %v", err)
			}
			if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err != nil {
				t.Fatalf("ordinary error prevented later compilation: %v", err)
			}
			if transport.closes.Load() != 0 || instance.closes.Load() != 0 {
				t.Fatal("ordinary error closed resources")
			}
		})
	}
}

func TestCompiledHostFaultOverridesCompileError(t *testing.T) {
	fault := errors.New("transport failed")
	s, _, transport := testCompiledSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		ctx.Value(sessionKey{}).(*sessionState).err = fault
		return []byte(`{"error":{"kind":"compile_a","message":"ill-typed"}}`), nil
	})
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); !errors.Is(err, fault) {
		t.Fatalf("host fault replaced by compile error: %v", err)
	}
	if transport.closes.Load() != 1 {
		t.Fatal("host fault kept solver alive")
	}
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); !errors.Is(err, ErrCompiledClosed) {
		t.Fatalf("host fault retained session: %v", err)
	}
}

func TestCompiledSharedDecoderFaultInvalidatesSession(t *testing.T) {
	for _, query := range []string{"equivalent", "implies"} {
		t.Run(query, func(t *testing.T) {
			s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(`{"report":{"results":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document","holds":false,"counterexample":{"request":{"principal":{"type":"User","id":"u"},"action":{"type":"Action","id":""},"resource":{"type":"Document","id":"d"},"context":{}},"entities":[],"a_decision":"allow","b_decision":"allow"}}]}}`), nil
			})
			s.environments = []RequestEnvironment{{PrincipalType: "User", Action: cedar.NewEntityUID("Action", ""), ResourceType: "Document"}}
			handle := CompiledPolicySet{session: s, id: 1}
			if _, err := s.check(context.Background(), query, handle, handle); err == nil || !strings.Contains(err.Error(), "does not violate the property") {
				t.Fatalf("contradictory report reached the wrong guard: %v", err)
			}
			if transport.closes.Load() != 1 {
				t.Fatal("shared decoder fault kept solver alive")
			}
			if _, err := s.check(context.Background(), query, handle, handle); !errors.Is(err, ErrCompiledClosed) {
				t.Fatalf("decoder fault retained session: %v", err)
			}
		})
	}
}

func TestCompiledCheckRequiresActionID(t *testing.T) {
	for _, action := range []string{`{"type":"Action"}`, `{"type":"Action","id":null}`, `{"type":"Action","id":""}`} {
		t.Run(action, func(t *testing.T) {
			s, instance, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(`{"report":{"results":[{"principal_type":"User","action":` + action + `,"resource_type":"Document","holds":true}]}}`), nil
			})
			s.environments = []RequestEnvironment{{PrincipalType: "User", Action: cedar.NewEntityUID("Action", ""), ResourceType: "Document"}}
			handle := CompiledPolicySet{session: s, id: 1}
			report, err := s.Equivalent(context.Background(), handle, handle)
			if action == `{"type":"Action","id":""}` {
				if err != nil || !report.Holds() || transport.closes.Load() != 0 || instance.closes.Load() != 0 {
					t.Fatalf("explicit empty action ID rejected: %+v %v", report, err)
				}
			} else if err == nil || transport.closes.Load() != 1 || instance.closes.Load() != 1 {
				t.Fatalf("incomplete action ID retained session: %+v %v", report, err)
			}
		})
	}
}

func TestCompiledEnvironmentJSONRoundTrip(t *testing.T) {
	want := RequestEnvironment{PrincipalType: "User", Action: cedar.NewEntityUID("Action", "view"), ResourceType: "Document"}
	data, err := json.Marshal([]RequestEnvironment{want})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `[{"principal_type":"User","action":{"type":"Action","id":"view"},"resource_type":"Document"}]` {
		t.Fatalf("selection JSON: %s", data)
	}
	var got []RequestEnvironment
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("selection round trip: %+v", got)
	}
	for _, env := range []RequestEnvironment{
		{PrincipalType: string([]byte{255}), Action: want.Action, ResourceType: want.ResourceType},
		{PrincipalType: want.PrincipalType, Action: cedar.NewEntityUID("Action", string([]byte{255})), ResourceType: want.ResourceType},
		{PrincipalType: want.PrincipalType, Action: want.Action, ResourceType: string([]byte{255})},
	} {
		if _, err := json.Marshal(env); err == nil {
			t.Fatal("environment JSON replaced invalid UTF-8")
		}
	}
}

func TestCompiledOpenRequiresEnvironmentFields(t *testing.T) {
	for _, response := range []string{
		`{}`,
		`{"environments":null}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action"},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action","id":null},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":null,"id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"","id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"action":{"type":"Action","id":""},"resource_type":"Document"}]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action","id":""}}]}`,
	} {
		t.Run(response, func(t *testing.T) {
			s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(response), nil
			})
			if err := s.execute(context.Background(), nil, nil, s.decodeOpen); err == nil {
				t.Fatal("incomplete environment accepted")
			}
			if transport.closes.Load() != 1 {
				t.Fatal("environment fault kept solver alive")
			}
		})
	}
	for _, response := range []string{
		`{"environments":[]}`,
		`{"environments":[{"principal_type":"User","action":{"type":"Action","id":""},"resource_type":"Document"}]}`,
	} {
		t.Run(response, func(t *testing.T) {
			s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
				return []byte(response), nil
			})
			if err := s.execute(context.Background(), nil, nil, s.decodeOpen); err != nil {
				t.Fatal(err)
			}
			if s.environments == nil || transport.closes.Load() != 0 {
				t.Fatal("valid environment response invalidated session")
			}
			if len(s.environments) == 1 && s.environments[0].Action != cedar.NewEntityUID("Action", "") {
				t.Fatalf("empty action ID changed: %+v", s.environments)
			}
		})
	}
}

func TestCompiledForeignAndReleasedHandlesBeforeGuest(t *testing.T) {
	s, instance, _ := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) { return []byte(`{"released":true}`), nil })
	foreign := CompiledPolicySet{session: &CompiledSession{}, id: 1}
	if err := s.Release(context.Background(), foreign); err == nil {
		t.Fatal("foreign handle accepted")
	}
	if err := s.Release(context.Background(), CompiledPolicySet{}); err == nil {
		t.Fatal("zero handle accepted")
	}
	if instance.calls.Load() != 0 {
		t.Fatal("foreign handle reached guest")
	}
	handle := CompiledPolicySet{session: s, id: 1}
	if err := s.Release(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(context.Background(), handle); err == nil {
		t.Fatal("released handle accepted")
	}
	if instance.calls.Load() != 1 {
		t.Fatal("released handle reached guest")
	}
}

func TestCompiledEnvironmentUTF8BeforeGuest(t *testing.T) {
	a := &Analyzer{maxSourceBytes: 1 << 20}
	for _, env := range []RequestEnvironment{
		{PrincipalType: string([]byte{255}), Action: cedar.NewEntityUID("Action", "view"), ResourceType: "Doc"},
		{PrincipalType: "User", Action: cedar.NewEntityUID("Action", string([]byte{255})), ResourceType: "Doc"},
		{PrincipalType: "User", Action: cedar.NewEntityUID("Action", "view"), ResourceType: string([]byte{255})},
	} {
		if _, err := a.OpenCompiled(context.Background(), cedar.SchemaFromCedar(querySchemaForUTF8), []RequestEnvironment{env}); err == nil {
			t.Fatal("invalid UTF-8 reached guest")
		}
	}
}

const querySchemaForUTF8 = `entity User; entity Doc; action view appliesTo {principal: User, resource: Doc, context: {}};`

func TestCompiledCloseInterruptsActiveCall(t *testing.T) {
	entered := make(chan struct{})
	s, instance, transport := testCompiledSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		close(entered)
		state := ctx.Value(sessionKey{}).(*sessionState)
		_, err := state.session.Read(make([]byte, 1))
		return nil, err
	})
	handle := CompiledPolicySet{session: s, id: 1}
	result := make(chan error, 1)
	go func() { _, err := s.Equivalent(context.Background(), handle, handle); result <- err }()
	<-entered
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("Close left active call successful")
	}
	if instance.closes.Load() != 1 || transport.closes.Load() != 1 {
		t.Fatal("Close failed to release resources once")
	}
}

func TestCompiledRealCVC5LifetimeClose(t *testing.T) {
	path := os.Getenv("CVC5")
	if path == "" {
		t.Skip("CVC5 is required for the real solver lifecycle test")
	}
	for iteration := 0; iteration < 100; iteration++ {
		s, instance, _ := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"report":{"results":[]}}`), nil
		})
		transport, err := CVC5(path).Start(s.lifetime)
		if err != nil {
			t.Fatal(err)
		}
		s.transport = transport
		if _, err := transport.Write([]byte("(check-sat)\n")); err != nil {
			t.Fatal(err)
		}
		if reply, err := bufio.NewReader(transport).ReadString('\n'); err != nil || reply != "sat\n" {
			t.Fatalf("solver reply %q: %v", reply, err)
		}
		s.cancel()
		if err := s.Close(); err != nil {
			t.Fatalf("iteration %d: canceled solver cleanup failed: %v", iteration, err)
		}
		if state := transport.(*process).cmd.ProcessState; state == nil {
			t.Fatal("solver process was not reaped")
		}
		if instance.closes.Load() != 1 {
			t.Fatal("lifetime cancellation retained the guest")
		}
		if _, err := s.Compile(context.Background(), cedar.PolicySet{}); !errors.Is(err, ErrCompiledClosed) {
			t.Fatalf("canceled lifetime retained session: %v", err)
		}
	}
}

func TestCompiledAnalyzerCloseInterruptsActiveCall(t *testing.T) {
	entered := make(chan struct{})
	s, instance, transport := testCompiledSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		close(entered)
		state := ctx.Value(sessionKey{}).(*sessionState)
		_, err := state.session.Read(make([]byte, 1))
		return nil, err
	})
	handle := CompiledPolicySet{session: s, id: 1}
	result := make(chan error, 1)
	go func() { _, err := s.Equivalent(context.Background(), handle, handle); result <- err }()
	<-entered
	if err := s.analyzer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("analyzer closure left active call successful")
	}
	if instance.closes.Load() != 1 || transport.closes.Load() != 1 {
		t.Fatal("analyzer closure failed to release resources once")
	}
}

func TestCompiledAnalyzerCloseCancelsPendingConstruction(t *testing.T) {
	started := make(chan struct{})
	transport := &compiledTestTransport{closed: make(chan struct{})}
	a := &Analyzer{maxSourceBytes: 1 << 20, maxSolverOutput: 1 << 20}
	a.solver = compiledTestSolver(func(ctx context.Context) (Session, error) {
		close(started)
		<-ctx.Done()
		return transport, nil
	})
	result := make(chan error, 1)
	go func() {
		_, err := a.OpenCompiled(context.Background(), cedar.SchemaFromCedar(querySchemaForUTF8), nil)
		result <- err
	}()
	<-started
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrCompiledClosed) {
			t.Fatalf("pending constructor error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("analyzer closure did not cancel constructor")
	}
	if transport.closes.Load() != 1 {
		t.Fatal("constructor retained late solver transport")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sessions) != 0 {
		t.Fatal("failed constructor retained session registration")
	}
}

type compiledCloseErrorTransport struct {
	*compiledTestTransport
	failure error
}

func (s *compiledCloseErrorTransport) Close() error {
	_ = s.compiledTestTransport.Close()
	return s.failure
}

func TestCompiledPendingConstructionReportsCloseErrors(t *testing.T) {
	for _, throughAnalyzer := range []bool{false, true} {
		name := "constructor_cancel"
		if throughAnalyzer {
			name = "analyzer_close"
		}
		t.Run(name, func(t *testing.T) {
			failure := errors.New("late solver cleanup failed")
			transport := &compiledCloseErrorTransport{compiledTestTransport: &compiledTestTransport{closed: make(chan struct{})}, failure: failure}
			started := make(chan struct{})
			a := &Analyzer{maxSourceBytes: 1 << 20, maxSolverOutput: 1 << 20}
			a.solver = compiledTestSolver(func(ctx context.Context) (Session, error) {
				a.mu.Lock()
				var pending *CompiledSession
				for session := range a.sessions {
					pending = session
				}
				a.mu.Unlock()
				close(started)
				<-ctx.Done()
				// Return the transport after cancellation marks the registered session closed.
				<-pending.done
				return transport, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opened := make(chan error, 1)
			go func() {
				_, err := a.OpenCompiled(ctx, cedar.SchemaFromCedar(querySchemaForUTF8), nil)
				opened <- err
			}()
			<-started
			if throughAnalyzer {
				if err := a.Close(context.Background()); !errors.Is(err, failure) {
					t.Fatalf("analyzer discarded cleanup error: %v", err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-opened:
				if !errors.Is(err, failure) || !errors.Is(err, ErrCompiledClosed) {
					t.Fatalf("constructor discarded cleanup or closed error: %v", err)
				}
				if !throughAnalyzer && !errors.Is(err, context.Canceled) {
					t.Fatalf("constructor discarded cancellation: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("pending constructor did not close")
			}
			if transport.closes.Load() != 1 {
				t.Fatal("late transport did not close once")
			}
			a.mu.Lock()
			registered := len(a.sessions)
			a.mu.Unlock()
			if registered != 0 {
				t.Fatal("failed constructor retained session registration")
			}
			if !throughAnalyzer {
				if err := a.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCompiledInputLimitLeavesSessionUsable(t *testing.T) {
	s, instance, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) { return []byte(`{"handle":2}`), nil })
	s.analyzer.maxSourceBytes = 1
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err == nil {
		t.Fatal("source limit ignored")
	}
	if instance.calls.Load() != 0 || transport.closes.Load() != 0 {
		t.Fatal("source limit changed session")
	}
	s.analyzer.maxSourceBytes = 1 << 20
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err != nil {
		t.Fatal(err)
	}
}

func TestCompiledReleasedIDCannotReturnAgain(t *testing.T) {
	var call atomic.Int32
	s, _, transport := testCompiledSession(t, func(context.Context, []byte) ([]byte, error) {
		if call.Add(1) == 1 {
			return []byte(`{"released":true}`), nil
		}
		return []byte(`{"handle":1}`), nil
	})
	if err := s.Release(context.Background(), CompiledPolicySet{session: s, id: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); err == nil {
		t.Fatal("released native ID was reused")
	}
	if transport.closes.Load() != 1 {
		t.Fatal("ID reuse did not invalidate session")
	}
}

func TestZeroCompiledSession(t *testing.T) {
	var s CompiledSession
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Compile(context.Background(), cedar.PolicySet{}); !errors.Is(err, ErrCompiledClosed) {
		t.Fatalf("zero session compile %v", err)
	}
}
