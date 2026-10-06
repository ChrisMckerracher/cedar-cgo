package compiled

import (
	"bufio"
	"context"
	"errors"
	"os"
	"testing"

	fixtures "github.com/ChrisMckerracher/cedar-cgo/analysis/internal/testsupport"
	"github.com/ChrisMckerracher/cedar-cgo/analysis/solver"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
)

func TestCompiledCloseInterruptsActiveCall(t *testing.T) {
	entered := make(chan struct{})
	var transport *fixtures.Transport
	s, instance, created := testSession(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		close(entered)
		_, err := transport.Read(make([]byte, 1))
		return nil, err
	})
	transport = created
	handle := PolicySet{session: s, id: 1}
	result := make(chan error, 1)
	go func() { _, err := s.Equivalent(context.Background(), handle, handle); result <- err }()
	<-entered
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("Close left active call successful")
	}
	if instance.closes.Load() != 1 || transport.Closes.Load() != 1 {
		t.Fatal("Close failed to release resources once")
	}
}

func TestCompiledRealCVC5LifetimeClose(t *testing.T) {
	path := os.Getenv("CVC5")
	if path == "" {
		t.Skip("CVC5 is required for the real solver lifecycle test")
	}
	for iteration := 0; iteration < 100; iteration++ {
		s, instance, _ := testSession(t, func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"report":{"results":[]}}`), nil
		})
		transport, err := solver.CVC5(path).Start(s.lifetime)
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
		if !transport.(interface{ Reaped() bool }).Reaped() {
			t.Fatal("solver process was not reaped")
		}
		if instance.closes.Load() != 1 {
			t.Fatal("lifetime cancellation retained native state")
		}
		if _, err := s.Compile(context.Background(), policy.PolicySet{}); !errors.Is(err, ErrClosed) {
			t.Fatalf("canceled lifetime retained session: %v", err)
		}
	}
}
