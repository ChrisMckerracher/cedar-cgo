package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type batchUID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (u batchUID) uid() cedar.EntityUID { return cedar.NewEntityUID(u.Type, u.ID) }

type batchFixture struct {
	Name, Schema, Policies string
	MaxIterations          uint32 `json:"max_iterations"`
	Request                struct {
		Principal, Action, Resource batchUID
		Context                     json.RawMessage
	}
	Batches []struct {
		Entities json.RawMessage
		Missing  []batchUID
	}
}

func batchedFixtures(t testing.TB) []batchFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/parity/batched/input.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []batchFixture
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func batchAuthorizer(t testing.TB, f batchFixture, limits cedar.Limits) *cedar.Authorizer {
	t.Helper()
	schema := cedar.SchemaFromCedar(f.Schema)
	a, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(f.Policies), Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}
func batchRequest(f batchFixture) cedar.Request {
	return cedar.Request{Principal: f.Request.Principal.uid(), Action: f.Request.Action.uid(), Resource: f.Request.Resource.uid(), Context: cedar.ContextFromJSON(f.Request.Context)}
}
func fixtureBatch(f batchFixture, n int) cedar.EntityLoadResult {
	if n >= len(f.Batches) {
		return cedar.EntityLoadResult{}
	}
	b := f.Batches[n]
	out := cedar.EntityLoadResult{Entities: b.Entities}
	for _, uid := range b.Missing {
		out.Missing = append(out.Missing, uid.uid())
	}
	return out
}

func TestBatchedNativeParity(t *testing.T) {
	data, err := os.ReadFile("../testdata/parity/batched/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected []struct {
		Name, Decision string
		Error          *string
		Calls          [][]batchUID
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	fixtures := batchedFixtures(t)
	if len(fixtures) != len(expected) {
		t.Fatal("native fixture count differs")
	}
	for i, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			want := expected[i]
			if want.Name != f.Name {
				t.Fatal("native fixture order differs")
			}
			a := batchAuthorizer(t, f, cedar.Limits{})
			calls := make([][]batchUID, 0)
			loader := cedar.EntityLoaderFunc(func(_ context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
				call := make([]batchUID, len(uids))
				for i, u := range uids {
					call[i] = batchUID{u.Type, u.ID}
				}
				result := fixtureBatch(f, len(calls))
				calls = append(calls, call)
				return result, nil
			})
			decision, err := a.AuthorizeBatched(context.Background(), batchRequest(f), loader, cedar.BatchedOptions{MaxIterations: f.MaxIterations})
			if decision.String() != want.Decision {
				t.Fatalf("decision %s, native %s", decision, want.Decision)
			}
			if want.Error == nil {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var ce *cedar.Error
				if !errors.As(err, &ce) || ce.Kind != cedar.KindBatched || ce.Message != *want.Error {
					t.Fatalf("error %v, native %s", err, *want.Error)
				}
			}
			if !reflect.DeepEqual(calls, want.Calls) {
				t.Fatalf("callback trace %v, native %v", calls, want.Calls)
			}
		})
	}
}

func TestBatchedCallbackFailures(t *testing.T) {
	f := batchedFixtures(t)[0]
	sentinel := errors.New("database unavailable")
	for _, tt := range []struct {
		name   string
		loader cedar.EntityLoaderFunc
		kind   cedar.ErrorKind
		cause  error
	}{
		{"error", func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			return cedar.EntityLoadResult{}, sentinel
		}, cedar.KindLoader, sentinel},
		{"panic", func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) { panic("callback panic") }, cedar.KindLoader, nil},
		{"malformed", func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			return cedar.EntityLoadResult{Entities: json.RawMessage("[")}, nil
		}, cedar.KindLoader, nil},
		{"wrong_shape", func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			return cedar.EntityLoadResult{Entities: json.RawMessage(`null`)}, nil
		}, cedar.KindEntities, nil},
		{"wrong_type", func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			return cedar.EntityLoadResult{Entities: json.RawMessage(`[{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":"yes"},"parents":[]}]`)}, nil
		}, cedar.KindEntities, nil},
		{"duplicate", func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			return cedar.EntityLoadResult{Missing: []cedar.EntityUID{{Type: "User", ID: "alice"}, {Type: "User", ID: "alice"}}}, nil
		}, cedar.KindEntities, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := batchAuthorizer(t, f, cedar.Limits{MaxInstances: 1})
			d, err := a.AuthorizeBatched(context.Background(), batchRequest(f), tt.loader, cedar.BatchedOptions{MaxIterations: 4})
			var ce *cedar.Error
			if d != cedar.Deny || !errors.As(err, &ce) || ce.Kind != tt.kind {
				t.Fatalf("got %s %v", d, err)
			}
			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Fatalf("lost callback cause: %v", err)
			}
			n := 0
			d, err = a.AuthorizeBatched(context.Background(), batchRequest(f), cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
				out := fixtureBatch(f, n)
				n++
				return out, nil
			}), cedar.BatchedOptions{MaxIterations: 2})
			if d != cedar.Allow || err != nil {
				t.Fatalf("recovery got %s %v", d, err)
			}
		})
	}
}

func TestBatchedLimits(t *testing.T) {
	f := batchedFixtures(t)[0]
	for _, tt := range []struct {
		name       string
		opts       cedar.BatchedOptions
		result     cedar.EntityLoadResult
		maxRequest int
		kind       cedar.ErrorKind
	}{
		{name: "iterations", opts: cedar.BatchedOptions{MaxIterations: 1025}, kind: cedar.KindLimit},
		{name: "negative_batch", opts: cedar.BatchedOptions{MaxBatchBytes: -1}, kind: cedar.KindInput},
		{name: "negative_total", opts: cedar.BatchedOptions{MaxLoaderBytes: -1}, kind: cedar.KindInput},
		{name: "oversize_batch_option", opts: cedar.BatchedOptions{MaxBatchBytes: (64 << 20) + 1}, kind: cedar.KindInput},
		{name: "uid_request", opts: cedar.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 1}, kind: cedar.KindLimit},
		{name: "total_request", opts: cedar.BatchedOptions{MaxIterations: 2, MaxLoaderBytes: 1}, kind: cedar.KindLimit},
		{name: "raw_result", opts: cedar.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: cedar.EntityLoadResult{Entities: json.RawMessage(strings.Repeat(" ", 129))}, kind: cedar.KindLimit},
		{name: "missing_count", opts: cedar.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: cedar.EntityLoadResult{Missing: make([]cedar.EntityUID, 128)}, kind: cedar.KindLimit},
		{name: "missing_id", opts: cedar.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: cedar.EntityLoadResult{Missing: []cedar.EntityUID{{Type: "User", ID: strings.Repeat("x", 129)}}}, kind: cedar.KindLimit},
		{name: "escaping", opts: cedar.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: cedar.EntityLoadResult{Missing: []cedar.EntityUID{{Type: "User", ID: strings.Repeat("\x00", 32)}}}, kind: cedar.KindLimit},
		{name: "total_result", opts: cedar.BatchedOptions{MaxIterations: 2, MaxLoaderBytes: 40}, kind: cedar.KindLimit},
		{name: "input", opts: cedar.BatchedOptions{MaxIterations: 2}, maxRequest: 1, kind: cedar.KindLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := batchAuthorizer(t, f, cedar.Limits{MaxRequestBytes: tt.maxRequest})
			d, err := a.AuthorizeBatched(context.Background(), batchRequest(f), cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) { return tt.result, nil }), tt.opts)
			var ce *cedar.Error
			if d != cedar.Deny || !errors.As(err, &ce) || ce.Kind != tt.kind {
				t.Fatalf("got %s %v, want %s", d, err, tt.kind)
			}
		})
	}
}

func TestBatchedCancellationAndPoolWait(t *testing.T) {
	f := batchedFixtures(t)[0]
	a := batchAuthorizer(t, f, cedar.Limits{MaxInstances: 1, CallTimeout: -1})
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := a.AuthorizeBatched(context.Background(), batchRequest(f), cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			close(entered)
			<-release
			return cedar.EntityLoadResult{}, errors.New("released")
		}), cedar.BatchedOptions{MaxIterations: 2})
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	calls := 0
	d, err := a.AuthorizeBatched(ctx, batchRequest(f), cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
		calls++
		return cedar.EntityLoadResult{}, nil
	}), cedar.BatchedOptions{MaxIterations: 2})
	close(release)
	<-done
	if d != cedar.Deny || !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatalf("pool wait: %s %v calls=%d", d, err, calls)
	}
	ctx, cancel = context.WithCancel(context.Background())
	loader := cedar.EntityLoaderFunc(func(ctx context.Context, _ []cedar.EntityUID) (cedar.EntityLoadResult, error) {
		cancel()
		<-ctx.Done()
		return fixtureBatch(f, 0), nil
	})
	d, err = a.AuthorizeBatched(ctx, batchRequest(f), loader, cedar.BatchedOptions{MaxIterations: 2})
	if d != cedar.Deny || !errors.Is(err, context.Canceled) {
		t.Fatalf("callback cancellation: %s %v", d, err)
	}
	if a.Stats().Discarded < 2 {
		t.Fatal("callback failures did not discard instances")
	}
}

func TestBatchedTimeoutAndConcurrency(t *testing.T) {
	f := batchedFixtures(t)[0]
	t.Run("timeout", func(t *testing.T) {
		a := batchAuthorizer(t, f, cedar.Limits{CallTimeout: 20 * time.Millisecond})
		d, err := a.AuthorizeBatched(context.Background(), batchRequest(f), cedar.EntityLoaderFunc(func(ctx context.Context, _ []cedar.EntityUID) (cedar.EntityLoadResult, error) {
			<-ctx.Done()
			return fixtureBatch(f, 0), nil
		}), cedar.BatchedOptions{MaxIterations: 2})
		if d != cedar.Deny || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %s %v", d, err)
		}
	})
	t.Run("concurrent_and_isolated", func(t *testing.T) {
		a := batchAuthorizer(t, f, cedar.Limits{MaxInstances: 4, CallTimeout: 5 * time.Second})
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				n := 0
				want := cedar.Allow
				if i%2 == 0 {
					want = cedar.Deny
				}
				d, err := a.AuthorizeBatched(context.Background(), batchRequest(f), cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
					out := fixtureBatch(f, n)
					if n == 1 && want == cedar.Deny {
						out.Entities = json.RawMessage(strings.ReplaceAll(string(out.Entities), "true", "false"))
					}
					n++
					return out, nil
				}), cedar.BatchedOptions{MaxIterations: 2})
				if d != want || err != nil || n != 2 {
					t.Errorf("call %d got %s %v rounds=%d", i, d, err, n)
				}
			}(i)
		}
		wg.Wait()
	})
}

func TestBatchedCachedEntitiesAndOwnership(t *testing.T) {
	f := batchedFixtures(t)[0]
	a := batchAuthorizer(t, f, cedar.Limits{MaxInstances: 1})
	req := batchRequest(f)
	req.Entities = cedar.EntitiesFromJSON(f.Batches[0].Entities)
	var retained []cedar.EntityUID
	d, err := a.AuthorizeBatched(context.Background(), req, cedar.EntityLoaderFunc(func(_ context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
		retained = uids
		return fixtureBatch(f, 1), nil
	}), cedar.BatchedOptions{MaxIterations: 2})
	if d != cedar.Allow || err != nil || len(retained) != 1 || retained[0].ID != "manager" {
		t.Fatalf("cache got %s %v ids=%v", d, err, retained)
	}
	n := 0
	d, err = a.AuthorizeBatched(context.Background(), batchRequest(f), cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
		n++
		return cedar.EntityLoadResult{}, nil
	}), cedar.BatchedOptions{MaxIterations: 1})
	if d != cedar.Deny || err == nil || n != 1 || retained[0].ID != "manager" {
		t.Fatalf("call data leaked: %s %v n=%d retained=%v", d, err, n, retained)
	}
}

func ExampleAuthorizer_AuthorizeBatched() {
	ctx := context.Background()
	rt, err := cedar.NewRuntime(ctx)
	if err != nil {
		panic(err)
	}
	defer rt.Close(ctx)
	schema := cedar.SchemaFromCedar(`entity User {active: Bool}; entity Document; action "read" appliesTo {principal: User, resource: Document, context: {}};`)
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource) when {principal.active};`)})
	if err != nil {
		panic(err)
	}
	defer a.Close()
	loader := cedar.EntityLoaderFunc(func(ctx context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
		if err := ctx.Err(); err != nil {
			return cedar.EntityLoadResult{}, err
		}
		// A real loader queries its entity store for precisely these UIDs.
		data, err := json.Marshal(cedar.NewEntities(cedar.Entity{UID: uids[0], Attrs: cedar.Record{"active": cedar.Bool(true)}}))
		return cedar.EntityLoadResult{Entities: data}, err
	})
	decision, err := a.AuthorizeBatched(ctx, cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: cedar.NewEntityUID("Action", "read"), Resource: cedar.NewEntityUID("Document", "guide")}, loader, cedar.BatchedOptions{MaxIterations: 4})
	if err != nil {
		panic(err)
	}
	fmt.Println(decision)
	// Output: allow
}

func TestBatchedLoaderCannotRedefineCachedEntities(t *testing.T) {
	schema := cedar.SchemaFromCedar(`entity User {enabled: Bool}; entity Resource {owner: User}; action "view" appliesTo {principal: User, resource: Resource, context: {}};`)
	cached := cedar.NewEntities(cedar.Entity{UID: cedar.NewEntityUID("User", "alice"), Attrs: cedar.Record{"enabled": cedar.Bool(false)}})
	resource := `{"uid":{"type":"Resource","id":"doc"},"attrs":{"owner":{"__entity":{"type":"User","id":"alice"}}},"parents":[]}`
	for _, viaRequest := range []bool{false, true} {
		for _, mode := range []string{"different", "identical", "missing"} {
			t.Run(fmt.Sprintf("request=%t/%s", viaRequest, mode), func(t *testing.T) {
				cfg := cedar.Config{Schema: &schema, Policies: cedar.PoliciesFromCedar(`permit(principal, action, resource) when {resource.owner.enabled};`)}
				req := cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Resource", "doc")}
				if viaRequest {
					req.Entities = cached
				} else {
					cfg.Entities = cached
				}
				a, err := testRuntime(t).NewAuthorizer(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				calls := 0
				d, err := a.AuthorizeBatched(context.Background(), req, cedar.EntityLoaderFunc(func(_ context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
					calls++
					if len(uids) != 1 || uids[0] != req.Resource {
						t.Fatalf("wanted only resource, got %v", uids)
					}
					out := cedar.EntityLoadResult{Entities: json.RawMessage("[" + resource + "]")}
					if mode == "missing" {
						out.Missing = []cedar.EntityUID{req.Principal}
					} else {
						out.Entities = json.RawMessage("[" + resource + `,{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":` + fmt.Sprint(mode == "different") + `},"parents":[]}]`)
					}
					return out, nil
				}), cedar.BatchedOptions{MaxIterations: 4})
				var ce *cedar.Error
				if d != cedar.Deny || !errors.As(err, &ce) || ce.Kind != cedar.KindEntities || calls != 1 {
					t.Fatalf("cache override got %s %v calls=%d", d, err, calls)
				}
			})
		}
	}
}

func TestBatchedSchemaAndRequestErrors(t *testing.T) {
	f := batchedFixtures(t)[0]
	for _, mode := range []string{"no_schema", "bad_request", "bad_context", "nil_loader"} {
		t.Run(mode, func(t *testing.T) {
			schema := cedar.SchemaFromCedar(f.Schema)
			cfg := cedar.Config{Policies: cedar.PoliciesFromCedar(f.Policies), Schema: &schema}
			if mode == "no_schema" {
				cfg.Schema = nil
			}
			a, err := testRuntime(t).NewAuthorizer(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			req := batchRequest(f)
			want := cedar.KindSchema
			switch mode {
			case "bad_request":
				req.Principal = cedar.NewEntityUID("Resource", "wrong")
				want = cedar.KindRequest
			case "bad_context":
				req.Context = cedar.ContextFromJSON([]byte(`{"unknown":true}`))
				want = cedar.KindContext
			case "nil_loader":
				want = cedar.KindInput
			}
			var loader cedar.EntityLoader = cedar.EntityLoaderFunc(func(context.Context, []cedar.EntityUID) (cedar.EntityLoadResult, error) {
				t.Error("invalid call reached callback")
				return cedar.EntityLoadResult{}, nil
			})
			if mode == "nil_loader" {
				loader = nil
			}
			d, err := a.AuthorizeBatched(context.Background(), req, loader, cedar.BatchedOptions{MaxIterations: 2})
			var ce *cedar.Error
			if d != cedar.Deny || !errors.As(err, &ce) || ce.Kind != want {
				t.Fatalf("got %s %v want %s", d, err, want)
			}
		})
	}
}
