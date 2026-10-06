package batched_test

import (
	context "context"
	json "encoding/json"
	errors "errors"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"

	strings "strings"
	sync "sync"
	testing "testing"
	time "time"
)

func TestBatchedLimits(t *testing.T) {
	f := BatchedFixtures(t)[0]
	for _, tt := range []struct {
		name       string
		opts       batched.BatchedOptions
		result     batched.EntityLoadResult
		maxRequest int
		kind       diagnostic.ErrorKind
	}{
		{name: "iterations", opts: batched.BatchedOptions{MaxIterations: 1025}, kind: diagnostic.KindLimit},
		{name: "negative_batch", opts: batched.BatchedOptions{MaxBatchBytes: -1}, kind: diagnostic.KindInput},
		{name: "negative_total", opts: batched.BatchedOptions{MaxLoaderBytes: -1}, kind: diagnostic.KindInput},
		{name: "oversize_batch_option", opts: batched.BatchedOptions{MaxBatchBytes: (64 << 20) + 1}, kind: diagnostic.KindInput},
		{name: "uid_request", opts: batched.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 1}, kind: diagnostic.KindLimit},
		{name: "total_request", opts: batched.BatchedOptions{MaxIterations: 2, MaxLoaderBytes: 1}, kind: diagnostic.KindLimit},
		{name: "raw_result", opts: batched.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: batched.EntityLoadResult{Entities: json.RawMessage(strings.Repeat(" ", 129))}, kind: diagnostic.KindLimit},
		{name: "missing_count", opts: batched.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: batched.EntityLoadResult{Missing: make([]entityuid.EntityUID, 128)}, kind: diagnostic.KindLimit},
		{name: "missing_id", opts: batched.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: batched.EntityLoadResult{Missing: []entityuid.EntityUID{{Type: "User", ID: strings.Repeat("x", 129)}}}, kind: diagnostic.KindLimit},
		{name: "escaping", opts: batched.BatchedOptions{MaxIterations: 2, MaxBatchBytes: 128}, result: batched.EntityLoadResult{Missing: []entityuid.EntityUID{{Type: "User", ID: strings.Repeat("\x00", 32)}}}, kind: diagnostic.KindLimit},
		{name: "total_result", opts: batched.BatchedOptions{MaxIterations: 2, MaxLoaderBytes: 40}, kind: diagnostic.KindLimit},
		{name: "input", opts: batched.BatchedOptions{MaxIterations: 2}, maxRequest: 1, kind: diagnostic.KindLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := BatchAuthorizer(t, f, authorization.Limits{MaxRequestBytes: tt.maxRequest})
			d, err := a.Batched().AuthorizeBatched(context.Background(), BatchRequest(f), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) { return tt.result, nil }), tt.opts)
			var ce *diagnostic.Error
			if d != cedarrequest.Deny || !errors.As(err, &ce) || ce.Kind != tt.kind {
				t.Fatalf("got %s %v, want %s", d, err, tt.kind)
			}
		})
	}
}

func TestBatchedCancellationAndPoolWait(t *testing.T) {
	f := BatchedFixtures(t)[0]
	a := BatchAuthorizer(t, f, authorization.Limits{MaxInstances: 1, CallTimeout: -1})
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := a.Batched().AuthorizeBatched(context.Background(), BatchRequest(f), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			close(entered)
			<-release
			return batched.EntityLoadResult{}, errors.New("released")
		}), batched.BatchedOptions{MaxIterations: 2})
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	calls := 0
	d, err := a.Batched().AuthorizeBatched(ctx, BatchRequest(f), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
		calls++
		return batched.EntityLoadResult{}, nil
	}), batched.BatchedOptions{MaxIterations: 2})
	close(release)
	<-done
	if d != cedarrequest.Deny || !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatalf("pool wait: %s %v calls=%d", d, err, calls)
	}
	ctx, cancel = context.WithCancel(context.Background())
	loader := batched.EntityLoaderFunc(func(ctx context.Context, _ []entityuid.EntityUID) (batched.EntityLoadResult, error) {
		cancel()
		<-ctx.Done()
		return FixtureBatch(f, 0), nil
	})
	d, err = a.Batched().AuthorizeBatched(ctx, BatchRequest(f), loader, batched.BatchedOptions{MaxIterations: 2})
	if d != cedarrequest.Deny || !errors.Is(err, context.Canceled) {
		t.Fatalf("callback cancellation: %s %v", d, err)
	}
	if a.Stats().Discarded < 2 {
		t.Fatal("callback failures did not discard instances")
	}
}

func TestBatchedTimeoutAndConcurrency(t *testing.T) {
	f := BatchedFixtures(t)[0]
	t.Run("timeout", func(t *testing.T) {
		a := BatchAuthorizer(t, f, authorization.Limits{CallTimeout: 20 * time.Millisecond})
		d, err := a.Batched().AuthorizeBatched(context.Background(), BatchRequest(f), batched.EntityLoaderFunc(func(ctx context.Context, _ []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			<-ctx.Done()
			return FixtureBatch(f, 0), nil
		}), batched.BatchedOptions{MaxIterations: 2})
		if d != cedarrequest.Deny || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %s %v", d, err)
		}
	})
	t.Run("concurrent_and_isolated", func(t *testing.T) {
		a := BatchAuthorizer(t, f, authorization.Limits{MaxInstances: 4, CallTimeout: 5 * time.Second})
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				n := 0
				want := cedarrequest.Allow
				if i%2 == 0 {
					want = cedarrequest.Deny
				}
				d, err := a.Batched().AuthorizeBatched(context.Background(), BatchRequest(f), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
					out := FixtureBatch(f, n)
					if n == 1 && want == cedarrequest.Deny {
						out.Entities = json.RawMessage(strings.ReplaceAll(string(out.Entities), "true", "false"))
					}
					n++
					return out, nil
				}), batched.BatchedOptions{MaxIterations: 2})
				if d != want || err != nil || n != 2 {
					t.Errorf("call %d got %s %v rounds=%d", i, d, err, n)
				}
			}(i)
		}
		wg.Wait()
	})
}
