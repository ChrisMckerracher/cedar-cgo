package native

import (
	"context"
	"fmt"
)

// Callback operates on a borrowed native buffer during one synchronous call.
// Call must not retain data. Entity load and solver write consume input.
// Entity read fills the buffer and returns zero. Solver read returns the written byte count.
type Callback interface {
	Call(context.Context, uint32, []byte) (int, error)
}

type callbackKey struct{}

func WithCallback(ctx context.Context, callback Callback) context.Context {
	return context.WithValue(ctx, callbackKey{}, callback)
}

func CallbackFrom(ctx context.Context) Callback {
	callback, _ := ctx.Value(callbackKey{}).(Callback)
	return callback
}

type callbackState struct {
	ctx      context.Context
	callback Callback
	err      error
}

func (s *callbackState) call(operation uint32, data []byte) (result int) {
	result = -1
	defer func() {
		if recovered := recover(); recovered != nil {
			s.err = fmt.Errorf("native callback panicked: %v", recovered)
		}
	}()
	if s.err != nil {
		return
	}
	if s.err = s.ctx.Err(); s.err != nil {
		return
	}
	var err error
	result, err = s.callback.Call(s.ctx, operation, data)
	if err != nil {
		s.err = err
		return -1
	}
	if s.err = s.ctx.Err(); s.err != nil {
		return -1
	}
	if result < 0 || (operation != 1 && result > len(data)) {
		s.err = fmt.Errorf("native callback returned invalid length %d", result)
		return -1
	}
	return
}
