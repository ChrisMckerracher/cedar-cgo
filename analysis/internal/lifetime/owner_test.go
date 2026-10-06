package lifetime

import (
	"context"
	"errors"
	"testing"
)

type closerFunc func() error

func (close closerFunc) Close() error { return close() }

func TestPendingConstructorCancellationRetainsCleanupError(t *testing.T) {
	var owner Owner
	lease, err := owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- owner.Close() }()
	<-lease.Context.Done()
	failure := errors.New("late cleanup failed")
	lease.Finish(failure)
	if err := <-finished; !errors.Is(err, failure) {
		t.Fatalf("cleanup error: %v", err)
	}
	if len(owner.leases) != 0 {
		t.Fatal("failed constructor retained registration")
	}
	if _, err := owner.Begin(context.Background()); err == nil {
		t.Fatal("closed owner accepted new work")
	}
}

func TestChildReleaseRemovesParentRegistration(t *testing.T) {
	var owner Owner
	lease, err := owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closes := 0
	child := closerFunc(func() error { closes++; lease.Release(); return nil })
	lease.Keep(child)
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if len(owner.leases) != 0 {
		t.Fatal("closed child retained parent registration")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatal("parent closed a released child again")
	}
}

func TestParentWaitsForLateChildAndPreservesCloseFailure(t *testing.T) {
	var owner Owner
	lease, err := owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- owner.Close() }()
	<-lease.Context.Done()
	failure := errors.New("child cleanup failed")
	closes := 0
	lease.Keep(closerFunc(func() error { closes++; lease.Release(); return failure }))
	if err := <-finished; !errors.Is(err, failure) {
		t.Fatalf("late child cleanup: %v", err)
	}
	if len(owner.leases) != 0 || closes != 1 {
		t.Fatal("parent retained late child")
	}
	if err := owner.Close(); !errors.Is(err, failure) || closes != 1 {
		t.Fatalf("repeated cleanup changed: %v", err)
	}
}

func TestCompletedCallReleasesOnlyItsRegistration(t *testing.T) {
	var owner Owner
	first, _ := owner.Begin(context.Background())
	second, _ := owner.Begin(context.Background())
	first.Finish(nil)
	if len(owner.leases) != 1 || second.Context.Err() != nil {
		t.Fatal("call release canceled unrelated work")
	}
	second.Finish(nil)
	if len(owner.leases) != 0 {
		t.Fatal("completed calls retained registration")
	}
}
