package compiled

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
)

func TestCompiledForeignAndReleasedHandlesBeforeGuest(t *testing.T) {
	s, instance, _ := testSession(t, func(context.Context, []byte) ([]byte, error) { return []byte(`{"released":true}`), nil })
	foreign := PolicySet{session: &Session{}, id: 1}
	if err := s.Release(context.Background(), foreign); err == nil {
		t.Fatal("foreign handle accepted")
	}
	if err := s.Release(context.Background(), PolicySet{}); err == nil {
		t.Fatal("zero handle accepted")
	}
	if instance.calls.Load() != 0 {
		t.Fatal("foreign handle reached native execution")
	}
	handle := PolicySet{session: s, id: 1}
	if err := s.Release(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(context.Background(), handle); err == nil {
		t.Fatal("released handle accepted")
	}
	if instance.calls.Load() != 1 {
		t.Fatal("released handle reached native execution")
	}
}

func TestCompiledReleasedIDCannotReturnAgain(t *testing.T) {
	var call atomic.Int32
	s, _, transport := testSession(t, func(context.Context, []byte) ([]byte, error) {
		if call.Add(1) == 1 {
			return []byte(`{"released":true}`), nil
		}
		return []byte(`{"handle":1}`), nil
	})
	if err := s.Release(context.Background(), PolicySet{session: s, id: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); err == nil {
		t.Fatal("released native ID was reused")
	}
	if transport.Closes.Load() != 1 {
		t.Fatal("ID reuse did not invalidate session")
	}
}

func TestZeroSession(t *testing.T) {
	var s Session
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Compile(context.Background(), policy.PolicySet{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero session compile %v", err)
	}
}
