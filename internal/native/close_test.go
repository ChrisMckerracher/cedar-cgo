package native

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestCloseRejectsQueuedCalls(t *testing.T) {
	ctx := context.Background()
	m, err := New(ctx, "authorizer")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)
	i, err := m.Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Hold active-call ownership while Close marks the state unavailable.
	i.mu.Lock()
	closed := make(chan error, 1)
	go func() { closed <- i.Close(ctx) }()
	deadline := time.Now().Add(time.Second)
	for !i.closing.Load() {
		if time.Now().After(deadline) {
			i.mu.Unlock()
			t.Fatal("Close did not reject new calls")
		}
		runtime.Gosched()
	}
	called := make(chan error, 1)
	go func() {
		_, err := i.Call(ctx, "cgw_load", []byte(`{"policies":{"format":"cedar","text":""}}`), 1024)
		called <- err
	}()
	i.mu.Unlock()
	if err := <-called; err == nil {
		t.Fatal("accepted a call after Close started")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
