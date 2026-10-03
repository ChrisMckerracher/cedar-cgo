package analysis

import (
	"context"
	"errors"
	"testing"
	"time"
)

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
