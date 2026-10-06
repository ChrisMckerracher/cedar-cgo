package compiled

import (
	"context"
	"errors"
	"testing"
	"time"

	fixtures "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/testsupport"
)

func TestCompiledQueuedCancellationPreservesActiveCall(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	s, instance, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
		close(entered)
		<-finish
		return []byte(`{"report":{"results":[]}}`), nil
	})
	handle := PolicySet{session: s, id: 1}
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
	if transport.Closes.Load() != 0 || instance.calls.Load() != 1 {
		t.Fatal("queued cancellation interrupted active resources")
	}
	close(finish)
	if err := <-active; err != nil {
		t.Fatal(err)
	}
	if transport.Closes.Load() != 0 {
		t.Fatal("successful active call closed solver")
	}
}

func TestCompiledActiveCancellationUnblocksSolverRead(t *testing.T) {
	entered := make(chan struct{})
	var transport *fixtures.Transport
	s, instance, created := testSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		close(entered)
		_, err := transport.Read(make([]byte, 1))
		return nil, err
	})
	transport = created
	handle := PolicySet{session: s, id: 1}
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
	if transport.Closes.Load() != 1 || instance.closes.Load() != 1 {
		t.Fatal("active cancellation did not release both resources")
	}
	if _, err := s.Equivalent(context.Background(), handle, handle); !errors.Is(err, ErrClosed) {
		t.Fatalf("faulted session reused %v", err)
	}
}

func TestCompiledActiveTimeoutInvalidatesSession(t *testing.T) {
	var transport *fixtures.Transport
	s, _, created := testSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		_, err := transport.Read(make([]byte, 1))
		return nil, err
	})
	transport = created
	s.config.Timeout = 10 * time.Millisecond
	handle := PolicySet{session: s, id: 1}
	if _, err := s.Equivalent(context.Background(), handle, handle); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error %v", err)
	}
	if transport.Closes.Load() != 1 {
		t.Fatal("timeout kept solver open")
	}
}
