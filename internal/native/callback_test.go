package native

import (
	"context"
	"errors"
	"testing"
)

type callbackFunc func(context.Context, uint32, []byte) (int, error)

func (f callbackFunc) Call(ctx context.Context, op uint32, data []byte) (int, error) {
	return f(ctx, op, data)
}

func TestCallbackOwnershipErrors(t *testing.T) {
	sentinel := errors.New("loader failed")
	for _, callback := range []callbackFunc{
		func(context.Context, uint32, []byte) (int, error) { return 0, sentinel },
		func(context.Context, uint32, []byte) (int, error) { panic("loader panic") },
		func(context.Context, uint32, []byte) (int, error) { return -2, nil },
		func(context.Context, uint32, []byte) (int, error) { return 4, nil },
	} {
		state := &callbackState{ctx: context.Background(), callback: callback}
		if n := state.call(2, make([]byte, 2)); n != -1 || state.err == nil {
			t.Fatalf("callback returned %d, %v", n, state.err)
		}
		if n := state.call(2, make([]byte, 2)); n != -1 {
			t.Fatal("reused failed callback")
		}
	}
	state := &callbackState{ctx: context.Background(), callback: callbackFunc(func(context.Context, uint32, []byte) (int, error) { return 10, nil })}
	if n := state.call(1, make([]byte, 2)); n != 10 || state.err != nil {
		t.Fatal("load response length incorrectly bounded by request")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state = &callbackState{ctx: ctx, callback: callbackFunc(func(context.Context, uint32, []byte) (int, error) {
		t.Fatal("called after cancellation")
		return 0, nil
	})}
	if n := state.call(1, nil); n != -1 || !errors.Is(state.err, context.Canceled) {
		t.Fatal("missed cancellation")
	}
}
