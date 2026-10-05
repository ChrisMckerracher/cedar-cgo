package native

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestNativeRuntimeLifetime(t *testing.T) {
	ctx := context.Background()
	m, err := New(ctx, "authorizer")
	if err != nil {
		t.Fatal(err)
	}
	i, err := m.Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	load := []byte(`{"policies":{"format":"cedar","text":"permit(principal,action,resource);"}}`)
	if _, err := i.Call(ctx, "cgw_load", load, 1<<20); err != nil {
		t.Fatal(err)
	}
	req := []byte(`{"principal":{"type":"User","id":"a"},"action":{"type":"Action","id":"view"},"resource":{"type":"Doc","id":"d"},"context":{}}`)
	var calls sync.WaitGroup
	for range 12 {
		calls.Go(func() {
			if _, err := i.Call(ctx, "cgw_authorize", req, 1<<20); err != nil {
				t.Error(err)
			}
		})
	}
	calls.Wait()
	for range 4 {
		calls.Go(func() {
			if err := m.Close(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	calls.Wait()
	if _, err := i.Call(ctx, "cgw_authorize", req, 1<<20); err == nil {
		t.Fatal("called closed state")
	}
	if _, err := m.Instantiate(ctx); err == nil {
		t.Fatal("created state after runtime close")
	}
	if err := i.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNativeEntryAndResponseRejection(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(canceled, "authorizer"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), "unknown"); err == nil {
		t.Fatal("accepted unknown module")
	}
	m, err := New(context.Background(), "authorizer")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if _, err := m.Instantiate(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	i, err := m.Instantiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Call(canceled, "cgw_load", nil, 100); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if i.Faulted() {
		t.Fatal("pre-entry cancellation invalidated state")
	}
	if _, err := i.Call(context.Background(), "cgw_load", []byte(`{"policies":{"format":"cedar","text":""}}`), 1); err == nil {
		t.Fatal("accepted oversized response")
	}
	if !i.Faulted() {
		t.Fatal("response failure did not invalidate state")
	}
	if _, err := i.Call(context.Background(), "cgw_load", nil, 100); err == nil {
		t.Fatal("reused faulted state")
	}
}
