package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
)

func nativeCallbackAuthorizer(t *testing.T, cap int) (*Authorizer, *execution.Runtime, request.Request) {
	t.Helper()
	runtime, err := execution.New(context.Background(), execution.WithMaxConcurrentCalls(cap))
	if err != nil {
		t.Fatal(err)
	}
	source := schema.SchemaFromCedar("entity User = {enabled: Bool}; entity Doc; action read appliesTo {principal: User, resource: Doc, context: {}};")
	authorizer, err := NewAuthorizer(context.Background(), runtime, Config{Schema: &source, Policies: policy.PoliciesFromCedar("permit(principal,action,resource) when {principal.enabled};"), Limits: Limits{MaxInstances: 8, CallTimeout: 5 * time.Second}})
	if err != nil {
		_ = runtime.Close(context.Background())
		t.Fatal(err)
	}
	return authorizer, runtime, request.Request{Principal: uid.NewEntityUID("User", "alice"), Action: uid.NewEntityUID("Action", "read"), Resource: uid.NewEntityUID("Doc", "one")}
}

func nativeLoadedEntity() batched.EntityLoadResult {
	return batched.EntityLoadResult{Entities: json.RawMessage(`[{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":true},"parents":[]}]`)}
}

func TestNativeConcurrencyCapIncludesCallbacks(t *testing.T) {
	authorizer, runtime, req := nativeCallbackAuthorizer(t, 2)
	defer runtime.Close(context.Background())
	defer authorizer.Close()
	entered, finish := make(chan struct{}, 8), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(finish) })
	var active, peak atomic.Int32
	loader := batched.EntityLoaderFunc(func(ctx context.Context, _ []uid.EntityUID) (batched.EntityLoadResult, error) {
		count := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); count > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, count) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-finish:
			return nativeLoadedEntity(), nil
		case <-ctx.Done():
			return batched.EntityLoadResult{}, ctx.Err()
		}
	})
	results := make(chan error, 8)
	for range 8 {
		go func() {
			decision, err := authorizer.Batched().AuthorizeBatched(context.Background(), req, loader, batched.BatchedOptions{MaxIterations: 4})
			if err == nil && decision != request.Allow {
				err = errors.New("native callback request was denied")
			}
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("two native callbacks did not enter")
		}
	}
	select {
	case <-entered:
		t.Fatal("runtime allowed more than two active callbacks")
	case <-time.After(25 * time.Millisecond):
	}
	once.Do(func() { close(finish) })
	for range 8 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if peak.Load() != 2 || authorizer.Stats().Discarded != 0 {
		t.Fatalf("native cap or fault statistics differ: peak %d, %+v", peak.Load(), authorizer.Stats())
	}
}

func TestNativeRuntimeCloseWaitsForActiveCallback(t *testing.T) {
	authorizer, runtime, req := nativeCallbackAuthorizer(t, 1)
	defer authorizer.Close()
	entered, finish := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(finish) })
	loader := batched.EntityLoaderFunc(func(context.Context, []uid.EntityUID) (batched.EntityLoadResult, error) {
		close(entered)
		<-finish
		return nativeLoadedEntity(), nil
	})
	result := make(chan error, 1)
	go func() {
		_, err := authorizer.Batched().AuthorizeBatched(context.Background(), req, loader, batched.BatchedOptions{MaxIterations: 4})
		result <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- runtime.Close(context.Background()) }()
	select {
	case <-closed:
		t.Fatal("runtime freed state while its callback was active")
	case <-time.After(25 * time.Millisecond):
	}
	once.Do(func() { close(finish) })
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	response, err := authorizer.Authorize(context.Background(), req)
	if response.Decision != request.Deny || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("closed runtime retained a usable client: %+v %v", response, err)
	}
}
